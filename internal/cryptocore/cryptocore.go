// Package cryptocore wraps OpenSSL, trezor routines and Go GCM crypto
// and provides a nonce generator.
package cryptocore

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha512"
	"encoding/hex"
	"fmt"
	"log"
	"runtime"
	"sync"
	"time"

	"github.com/conejoninja/tesoro/pb/messages"

	"github.com/rfjakob/eme"

	"github.com/rfjakob/gocryptfs/internal/siv_aead"
	"github.com/rfjakob/gocryptfs/internal/stupidgcm"
	"github.com/rfjakob/gocryptfs/internal/tlog"
)

const (
	// KeyLen is the cipher key length in bytes.  32 for AES-256.
	KeyLen = 32
	// AuthTagLen is the length of a GCM auth tag in bytes.
	AuthTagLen = 16
)

// AEADTypeEnum indicates the type of AEAD backend in use.
type AEADTypeEnum int

const (
	// BackendOpenSSL specifies the OpenSSL backend.
	BackendOpenSSL AEADTypeEnum = 3
	// BackendGoGCM specifies the Go based GCM backend.
	BackendGoGCM AEADTypeEnum = 4
	// BackendAESSIV specifies an AESSIV backend.
	BackendAESSIV AEADTypeEnum = 5
	// BackendTrezorAES specifies the AES backend using "Trezor" (hardware crypto device)
	BackendAESTrezor AEADTypeEnum = 6
)

// CryptoCore is the low level crypto implementation.
type CryptoCore struct {
	// EME is used for filename encryption.
	emeCipher eme.EMECipher
	// GCM or AES-SIV. This is used for content encryption.
	aeadCipher cipher.AEAD
	// Which backend is behind AEADCipher?
	AEADBackend AEADTypeEnum
	// GCM needs unique IVs (nonces)
	IVGenerator *nonceGenerator
	IVLen       int
	// A timestamp of the last use of this crypto core
	LastAccessTime time.Time

	// a mutex :)
	mutex *sync.Mutex

	// a trezor (to decrypt master key)
	trezor *trezor

	// remembering arguments passed to New()
	useHKDF                  bool
	forceDecode              bool
	trezorKeyname            string
	trezorEncryptMasterkey   bool
	trezorEncryptedMasterKey []byte
}

// New returns a new CryptoCore object or panics.
//
// Even though the "GCMIV128" feature flag is now mandatory, we must still
// support 96-bit IVs here because they were used for encrypting the master
// key in gocryptfs.conf up to gocryptfs v1.2. v1.3 switched to 128 bits.
//
// Note: "key" is either the scrypt hash of the password (when decrypting
// a config file) or the masterkey (when finally mounting the filesystem).
func New(key []byte, aeadType AEADTypeEnum, IVBitLen int, useHKDF bool, trezorEncryptMasterkey bool, trezorKeyname string, forceDecode bool) *CryptoCore {
	if len(key) != KeyLen {
		log.Panic(fmt.Sprintf("Unsupported key length %d", len(key)))
	}
	// We want the IV size in bytes
	IVLen := IVBitLen / 8

	cc := CryptoCore{
		AEADBackend:            aeadType,
		IVGenerator:            &nonceGenerator{nonceLen: IVLen},
		IVLen:                  IVLen,
		LastAccessTime:         time.Now(),
		useHKDF:                useHKDF,
		forceDecode:            forceDecode,
		trezorKeyname:          trezorKeyname,
		trezorEncryptMasterkey: trezorEncryptMasterkey,
		mutex: &sync.Mutex{},
	}

	// if it's a Trezor used than we prefer to initialize ciphers lazely to hold
	// decrypted master key in RAM as little as possible
	if !trezorEncryptMasterkey {
		cc.initCiphers(key)
		return &cc
	}

	// if it's a Trezor used than we prefer to periodically wipe out decrypted
	// master key from RAM (and reinitialize it on demand)
	cc.trezor = NewTrezor()
	cc.trezorEncryptedMasterKey = key
	go func() {
		for {
			time.Sleep(time.Second * 5)
			tlog.Debug.Printf("CryptoCore New(): cc.AreCiphersInitialized(): %v", cc.AreCiphersInitialized())
			if !cc.AreCiphersInitialized() {
				continue
			}
			tlog.Debug.Printf("CryptoCore New(): timediff: %v", time.Now().Unix()-cc.LastAccessTime.Unix())
			if time.Now().Unix()-cc.LastAccessTime.Unix() <= 60 {
				continue
			}
			cc.Wipe()
			tlog.Debug.Printf("CryptoCore New(): Wipe()-ed")
		}
	}()

	return &cc
}

func (cc CryptoCore) AreCiphersInitialized() bool {
	return cc.emeCipher != nil
}

func (cc *CryptoCore) Lock() {
	if !cc.trezorEncryptMasterkey { // locking is required only if trezorEncryptMasterkey == true (see function "New()")
		return
	}
	cc.mutex.Lock()
}
func (cc *CryptoCore) Unlock() {
	if !cc.trezorEncryptMasterkey {
		return
	}
	cc.mutex.Unlock()
}

func (cc *CryptoCore) initCiphers(key []byte) {
	// Initialize EME for filename encryption.
	var emeCipher eme.EMECipher
	var err error
	{
		var emeBlockCipher cipher.Block
		if cc.useHKDF {
			emeKey := hkdfDerive(key, hkdfInfoEMENames, KeyLen)
			emeBlockCipher, err = aes.NewCipher(emeKey)
			for i := range emeKey {
				emeKey[i] = 0
			}
		} else {
			emeBlockCipher, err = aes.NewCipher(key)
		}
		if err != nil {
			log.Panic(err)
		}
		emeCipher = eme.New(emeBlockCipher)
	}

	// Initialize an AEAD cipher for file content encryption.
	var aeadCipher cipher.AEAD
	if cc.AEADBackend == BackendOpenSSL || cc.AEADBackend == BackendGoGCM {
		var gcmKey []byte
		if cc.useHKDF {
			gcmKey = hkdfDerive(key, hkdfInfoGCMContent, KeyLen)
		} else {
			gcmKey = append([]byte{}, key...)
		}
		switch cc.AEADBackend {
		case BackendOpenSSL:
			if cc.IVLen != 16 {
				log.Panic("stupidgcm only supports 128-bit IVs")
			}
			aeadCipher = stupidgcm.New(gcmKey, cc.forceDecode)
		case BackendGoGCM:
			goGcmBlockCipher, err := aes.NewCipher(gcmKey)
			if err != nil {
				log.Panic(err)
			}
			aeadCipher, err = cipher.NewGCMWithNonceSize(goGcmBlockCipher, cc.IVLen)
			if err != nil {
				log.Panic(err)
			}
		}
		for i := range gcmKey {
			gcmKey[i] = 0
		}
	} else if cc.AEADBackend == BackendAESSIV {
		if cc.IVLen != 16 {
			// SIV supports any nonce size, but we only use 16.
			log.Panic("AES-SIV must use 16-byte nonces")
		}
		// AES-SIV uses 1/2 of the key for authentication, 1/2 for
		// encryption, so we need a 64-bytes key for AES-256. Derive it from
		// the 32-byte master key using HKDF, or, for older filesystems, with
		// SHA256.
		var key64 []byte
		if cc.useHKDF {
			key64 = hkdfDerive(key, hkdfInfoSIVContent, siv_aead.KeyLen)
		} else {
			s := sha512.Sum512(key)
			key64 = s[:]
		}
		aeadCipher = siv_aead.New(key64)
		for i := range key64 {
			key64[i] = 0
		}
	} else {
		log.Panic("unknown backend cipher")
	}

	cc.emeCipher = emeCipher
	cc.aeadCipher = aeadCipher
}

func (cc CryptoCore) trezorGetDecryptedMasterKey() []byte {
	cc.trezor.CheckTrezorConnection()

	hexValue := hex.EncodeToString(cc.trezorEncryptedMasterKey)
	if len(hexValue)%2 != 0 {
		log.Panic("len(hexValue)%2 != 0")
	}
	for len(hexValue)%32 != 0 {
		hexValue += "00"
	}

	result, msgType := cc.trezor.CipherKeyValue(false, cc.trezorKeyname, []byte(hexValue), []byte{}, false, true)

	if msgType == messages.MessageType_MessageType_Failure {
		log.Panicf("trezor: %v", string(result))
	}

	return result
}

func (cc *CryptoCore) AEADCipherOpen(dst, nonce, ciphertext, additionalData []byte) ([]byte, error) {
	cc.Lock()
	defer cc.Unlock()
	if !cc.AreCiphersInitialized() {
		cc.initCiphers(cc.trezorGetDecryptedMasterKey())
	}
	cc.LastAccessTime = time.Now()
	return cc.aeadCipher.Open(dst, nonce, ciphertext, additionalData)
}

func (cc *CryptoCore) AEADCipherSeal(dst, nonce, ciphertext, additionalData []byte) []byte {
	cc.Lock()
	defer cc.Unlock()
	if !cc.AreCiphersInitialized() {
		cc.initCiphers(cc.trezorGetDecryptedMasterKey())
	}
	cc.LastAccessTime = time.Now()
	return cc.aeadCipher.Seal(dst, nonce, ciphertext, additionalData)
}

func (cc *CryptoCore) EMECipherEncrypt(tweak []byte, inputData []byte) []byte {
	cc.Lock()
	defer cc.Unlock()
	if !cc.AreCiphersInitialized() {
		cc.initCiphers(cc.trezorGetDecryptedMasterKey())
	}
	cc.LastAccessTime = time.Now()
	return cc.emeCipher.Encrypt(tweak, inputData)
}

func (cc *CryptoCore) EMECipherDecrypt(tweak []byte, inputData []byte) []byte {
	cc.Lock()
	defer cc.Unlock()
	if !cc.AreCiphersInitialized() {
		cc.initCiphers(cc.trezorGetDecryptedMasterKey())
	}
	cc.LastAccessTime = time.Now()
	return cc.emeCipher.Decrypt(tweak, inputData)
}

type ccEMECipher struct {
	cryptoCore *CryptoCore
}

func (cc *CryptoCore) EMECipher() *ccEMECipher {
	return &ccEMECipher{
		cryptoCore: cc,
	}
}

func (cipher *ccEMECipher) Encrypt(tweak []byte, inputData []byte) []byte {
	return cipher.cryptoCore.EMECipherEncrypt(tweak, inputData)
}

func (cipher *ccEMECipher) Decrypt(tweak []byte, inputData []byte) []byte {
	return cipher.cryptoCore.EMECipherDecrypt(tweak, inputData)
}

type wiper interface {
	Wipe()
}

// Wipe tries to wipe secret keys from memory by overwriting them with zeros
// and/or setting references to nil.
//
// This is not bulletproof due to possible GC copies, but
// still raises to bar for extracting the key.
func (c *CryptoCore) Wipe() {
	c.Lock()
	defer c.Unlock()
	be := c.AEADBackend
	if be == BackendOpenSSL || be == BackendAESSIV {
		tlog.Debug.Printf("CryptoCore.Wipe: Wiping AEADBackend %d key", be)
		// We don't use "x, ok :=" because we *want* to crash loudly if the
		// type assertion fails.
		w := c.aeadCipher.(wiper)
		w.Wipe()
	} else {
		tlog.Debug.Printf("CryptoCore.Wipe: Only nil'ing stdlib refs")
	}
	// We have no access to the keys (or key-equivalents) stored inside the
	// Go stdlib. Best we can is to nil the references and force a GC.
	c.aeadCipher = nil
	c.emeCipher = nil
	runtime.GC()
}
