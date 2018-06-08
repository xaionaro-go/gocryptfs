package main

import (
	"reflect"
	"testing"
)

type testcase struct {
	// i is the input
	i []string
	// o is the expected output
	o []string
	// Do we expect an error?
	e bool
}

// TestPrefixOArgs checks that the "-o x,y,z" parsing works correctly.
func TestPrefixOArgs(t *testing.T) {
	testcases := []testcase{
		{
			i: nil,
			o: nil,
		},
		{
			i: []string{"gocryptfs"},
			o: []string{"gocryptfs"},
		},
		{
			i: []string{"gocryptfs", "-v"},
			o: []string{"gocryptfs", "-v"},
		},
		{
			i: []string{"gocryptfs", "foo", "bar", "-v"},
			o: []string{"gocryptfs", "foo", "bar", "-v"},
		},
		{
			i: []string{"gocryptfs", "foo", "bar", "-o", "a"},
			o: []string{"gocryptfs", "-a", "foo", "bar"},
		},
		{
			i: []string{"gocryptfs", "foo", "bar", "-o", "a,b,xxxxx"},
			o: []string{"gocryptfs", "-a", "-b", "-xxxxx", "foo", "bar"},
		},
		{
			i: []string{"gocryptfs", "foo", "bar", "-d", "-o=a,b,xxxxx"},
			o: []string{"gocryptfs", "-a", "-b", "-xxxxx", "foo", "bar", "-d"},
		},
		{
			i: []string{"gocryptfs", "foo", "bar", "-oooo", "a,b,xxxxx"},
			o: []string{"gocryptfs", "foo", "bar", "-oooo", "a,b,xxxxx"},
		},
		// https://github.com/mhogomchungu/sirikali/blob/a36d91d3e39f0c1eb9a79680ed6c28ddb6568fa8/src/siritask.cpp#L192
		{
			i: []string{"gocryptfs", "-o", "rw", "--config", "fff", "ccc", "mmm"},
			o: []string{"gocryptfs", "-rw", "--config", "fff", "ccc", "mmm"},
		},
		// "--" should also block "-o" parsing.
		{
			i: []string{"gocryptfs", "foo", "bar", "--", "-o", "a"},
			o: []string{"gocryptfs", "foo", "bar", "--", "-o", "a"},
		},
		{
			i: []string{"gocryptfs", "--", "-o", "a"},
			o: []string{"gocryptfs", "--", "-o", "a"},
		},
		// This should error out
		{
			i: []string{"gocryptfs", "foo", "bar", "-o"},
			e: true,
		},
	}
	for _, tc := range testcases {
		o, err := prefixOArgs(tc.i)
		e := (err != nil)
		if !reflect.DeepEqual(o, tc.o) || e != tc.e {
			t.Errorf("\n  in=%q\nwant=%q err=%v\n got=%q err=%v", tc.i, tc.o, tc.e, o, e)
		}
	}
}
