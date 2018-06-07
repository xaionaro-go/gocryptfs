package cryptocore

import (
	"crypto/cipher"
	"encoding/hex"
	"fmt"
	"log"
	"os"

	"github.com/conejoninja/tesoro"
	"github.com/conejoninja/tesoro/pb/messages"
	"github.com/conejoninja/tesoro/transport"
	"github.com/xaionaro-go/pinentry"
	"github.com/zserge/hid"
)

const (
	tagLen = 16
)

type trezor struct {
	tesoro.Client
	pinentry pinentry.PinentryClient
}

func NewTrezor() *trezor {
	pinentryClient, _ := pinentry.NewPinentryClient()
	trezor := trezor{
		pinentry: pinentryClient,
	}
	trezor.Reconnect()
	return &trezor
}

type trezorCipher struct {
	*trezor
	keyName string
}

func (trezor *trezor) NewAEADCipher(keyName string) cipher.AEAD {
	return trezorCipher{
		trezor:  trezor,
		keyName: keyName,
	}
}

func (trezor *trezor) Reconnect() {
	success := false
	for !success {
		hid.UsbWalk(func(device hid.Device) {
			info := device.Info()
			if info.Vendor == 21324 && info.Product == 1 && info.Interface == 0 {
				var t transport.TransportHID
				t.SetDevice(device)
				trezor.Client.SetTransport(&t)
				success = true
				return
			}
		})
		if !success {
			log.Print("No Trezor devices found.")
			trezor.pinentry.SetPrompt("No Trezor devices found.")
			trezor.pinentry.SetDesc("Please check connection to your Trezor device.")
			trezor.pinentry.SetOK("Retry")
			trezor.pinentry.SetCancel("Unmount")
			shouldContinue := trezor.pinentry.Confirm()
			if !shouldContinue {
				log.Print("Cannot continue without Trezor devices.")
				os.Exit(0)
			}
		} else if !trezor.Ping() {
			log.Panic("An unexpected behaviour of the trezor device.")
		}
	}
}

func (trezor *trezor) call(msg []byte) (string, uint16) {
	result, msgType := trezor.Client.Call(msg)

	switch messages.MessageType(msgType) {
	case messages.MessageType_MessageType_PinMatrixRequest:

		trezor.pinentry.SetPrompt("PIN")
		trezor.pinentry.SetDesc("")
		pin, err := trezor.pinentry.GetPin()
		if err != nil {
			log.Print("Error", err)
		}
		result, msgType = trezor.call(trezor.Client.PinMatrixAck(string(pin)))

	case messages.MessageType_MessageType_ButtonRequest:

		result, msgType = trezor.call(trezor.Client.ButtonAck())

	case messages.MessageType_MessageType_PassphraseRequest:

		trezor.pinentry.SetPrompt("Passphrase")
		trezor.pinentry.SetDesc("")
		passphrase, err := trezor.pinentry.GetPin()
		if err != nil {
			log.Print("Error", err)
		}
		result, msgType = trezor.call(trezor.Client.PassphraseAck(string(passphrase)))

	case messages.MessageType_MessageType_WordRequest:

		trezor.pinentry.SetPrompt("Word")
		trezor.pinentry.SetDesc("")
		word, err := trezor.pinentry.GetPin()
		if err != nil {
			log.Print("Error", err)
		}
		result, msgType = trezor.call(trezor.Client.WordAck(string(word)))

	//case messages.MessageType_MessageType_CipheredKeyValue:
		//log.Panic("Not implemented, yet")

	}

	return result, msgType
}

func (trezor *trezor) Ping() bool {
	str, _ := trezor.call(trezor.Client.Ping("gocryptfs", false, false, false))
	return str == "gocryptfs"
}

func (trezor *trezor) CheckTrezorConnection() {
	if trezor.Ping() {
		return
	}

	trezor.Reconnect()
}

func (trezor *trezor) CipherKeyValue(isToEncrypt bool, keyName string, data, iv []byte, askOnEncode, askOnDecode bool) []byte {
	path := `m/71'/a6'/3'/45'/96'`
	result, msgType := trezor.call(trezor.Client.CipherKeyValue(isToEncrypt, keyName, data, tesoro.StringToBIP32Path(path), iv, askOnEncode, askOnDecode))
	log.Print("msgType == ", msgType)
	return []byte(result)
}

func (cipher trezorCipher) NonceSize() int {
	return 16
}

func (cipher trezorCipher) Overhead() int {
	return 0
}

func (cipher trezorCipher) Seal(dst, nonce, plaintext, additionalData []byte) []byte {
	cipher.trezor.CheckTrezorConnection()
	//outLen := len(plaintext) + tagLen
	result := cipher.trezor.CipherKeyValue(true, cipher.keyName, append(additionalData[:tagLen], plaintext...), nonce, false, true)
	/*for len(result) < outLen {
		result = append(result, byte(0))
	}*/
	//dst = append(dst, result[:outLen]...)
	dst = append(dst, result...)
	return dst
}

func (cipher trezorCipher) Open(dst, nonce, ciphertext, additionalData []byte) ([]byte, error) {
	cipher.trezor.CheckTrezorConnection()
	hexValue := hex.EncodeToString(ciphertext)
	if len(hexValue) % 2 != 0 {
		log.Panic(len(hexValue) % 2 != 0)
	}
	for len(hexValue) % 32 != 0 {
		hexValue += "00"
	}
	result := cipher.trezor.CipherKeyValue(false, cipher.keyName, []byte(hexValue), nonce, false, true)
	log.Print(len(ciphertext), len(result), tagLen, len(additionalData))
	additionalDataExtracted := result[:tagLen]
	if string(additionalData[:tagLen]) != string(additionalDataExtracted) {
		return dst, fmt.Errorf("trezor: cannot decrypt (wrong trezor or passphrase?): %v != %v", additionalData[:tagLen], additionalDataExtracted, string(result))
	}
	dst = append(dst, result[tagLen:]...)
	return dst, nil
}
