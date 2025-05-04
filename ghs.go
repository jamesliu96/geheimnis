package main

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"syscall/js"

	"github.com/jamesliu96/geheim"
)

func printf(format string, a ...any) { fmt.Fprintf(os.Stderr, format, a...) }

func check(err error) {
	if err != nil {
		printf("error: %s\n", err)
		os.Exit(1)
	}
}

func main() {
	global := js.Global()
	uint8Array := global.Get("Uint8Array")
	x := global.Get("__x__")
	x.Delete("output")
	if !x.Get("__init__").Truthy() {
		x.Set("CipherString", geheim.CipherString)
		x.Set("DefaultCipher", int(geheim.DefaultCipher))
		x.Set("CipherDesc", geheim.CipherDesc)
		x.Set("HashString", geheim.HashString)
		x.Set("DefaultHash", int(geheim.DefaultHash))
		x.Set("HashDesc", geheim.HashDesc)
		x.Set("KDFString", geheim.KDFString)
		x.Set("DefaultKDF", int(geheim.DefaultKDF))
		x.Set("KDFDesc", geheim.KDFDesc)
		x.Set("MinSec", geheim.MinSec)
		x.Set("MaxSec", geheim.MaxSec)
		x.Set("DefaultSec", int(geheim.DefaultSec))
		x.Set("SecString", geheim.SecString)
		x.Set("SecDesc", geheim.SecDesc)
		x.Set("__init__", true)
		return
	}
	input := x.Get("input")
	if !input.Truthy() {
		check(errors.New("no input"))
	}
	key := x.Get("key")
	if !key.Truthy() {
		check(errors.New("no key"))
	}
	keyBytes := []byte(key.String())
	inputBytes := make([]byte, input.Length())
	js.CopyBytesToGo(inputBytes, input)
	inputBuffer := bytes.NewBuffer(inputBytes)
	size := int64(inputBuffer.Len())
	outputBuffer := bytes.NewBuffer(nil)
	printFunc := geheim.NewDefaultPrintFunc(os.Stderr)
	var err error
	var auth []byte
	if x.Get("archive").Truthy() {
		if x.Get("decrypt").Truthy() {
			auth, _, err = geheim.DecryptArchive(inputBuffer, outputBuffer, keyBytes, printFunc)
		} else {
			auth, err = geheim.EncryptArchive(inputBuffer, outputBuffer, keyBytes, size, geheim.Cipher(x.Get("cipher").Int()), geheim.Hash(x.Get("hash").Int()), geheim.KDF(x.Get("kdf").Int()), x.Get("sec").Int(), printFunc)
		}
	} else {
		if x.Get("decrypt").Truthy() {
			var authexBytes []byte
			if authex := x.Get("auth"); authex.Truthy() {
				authexBytes, err = hex.DecodeString(authex.String())
				check(err)
			}
			auth, err = geheim.DecryptVerify(inputBuffer, outputBuffer, keyBytes, authexBytes, printFunc)
		} else {
			auth, err = geheim.Encrypt(inputBuffer, outputBuffer, keyBytes, geheim.Cipher(x.Get("cipher").Int()), geheim.Hash(x.Get("hash").Int()), geheim.KDF(x.Get("kdf").Int()), x.Get("sec").Int(), printFunc)
		}
	}
	x.Set("auth", hex.EncodeToString(auth))
	check(err)
	output := uint8Array.New(outputBuffer.Len())
	js.CopyBytesToJS(output, outputBuffer.Bytes())
	x.Set("output", output)
}
