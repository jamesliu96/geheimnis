package main

import (
	"bytes"
	"encoding/hex"
	"log"
	"syscall/js"

	"github.com/jamesliu96/geheim"
)

func main() {
	log.Println("launch")
	defer log.Println("exit")
	global := js.Global()
	uint8Array := global.Get("Uint8Array")
	x := global.Get("__x__")
	x.Set("__out__", false)
	init := x.Get("__init__")
	if !init.Truthy() {
		x.Set("CipherString", geheim.GetCipherString())
		x.Set("DefaultCipher", int(geheim.DefaultCipher))
		x.Set("ModeString", geheim.GetModeString())
		x.Set("DefaultMode", int(geheim.DefaultMode))
		x.Set("KDFString", geheim.GetKDFString())
		x.Set("DefaultKDF", int(geheim.DefaultKDF))
		x.Set("MACString", geheim.GetMACString())
		x.Set("DefaultMAC", int(geheim.DefaultMAC))
		x.Set("MDString", geheim.GetMDString())
		x.Set("DefaultMD", int(geheim.DefaultMD))
		x.Set("MinSec", geheim.MinSec)
		x.Set("MaxSec", geheim.MaxSec)
		x.Set("DefaultSec", geheim.DefaultSec)
		x.Set("__init__", true)
		return
	}
	input := x.Get("input")
	pass := x.Get("pass")
	if !input.Truthy() {
		log.Fatalln("error:", "no input")
		return
	}
	if !pass.Truthy() {
		log.Fatalln("error:", "no passcode")
		return
	}
	inputBytes := make([]byte, input.Length())
	js.CopyBytesToGo(inputBytes, input)
	inputBuffer := bytes.NewBuffer(inputBytes)
	outputBuffer := new(bytes.Buffer)
	if x.Get("decrypt").Truthy() {
		signex := x.Get("sign")
		var signexBytes []byte
		if signex.Truthy() {
			if b, err := hex.DecodeString(signex.String()); err == nil {
				signexBytes = b
			} else {
				log.Fatalln("error:", err)
				return
			}
		}
		sign, err := geheim.DecryptVerify(inputBuffer, outputBuffer, []byte(pass.String()), signexBytes, geheim.DefaultPrintFunc)
		if err != nil {
			log.Fatalln("error:", err)
			return
		}
		output := uint8Array.New(outputBuffer.Len())
		js.CopyBytesToJS(output, outputBuffer.Bytes())
		x.Set("output", output)
		x.Set("sign", hex.EncodeToString(sign))
		x.Set("__out__", true)
	} else {
		sign, err := geheim.Encrypt(inputBuffer, outputBuffer, []byte(pass.String()), geheim.Cipher(x.Get("cipher").Int()), geheim.Mode(x.Get("mode").Int()), geheim.KDF(x.Get("kdf").Int()), geheim.MAC(x.Get("mac").Int()), geheim.MD(x.Get("md").Int()), x.Get("sec").Int(), geheim.DefaultPrintFunc)
		if err != nil {
			log.Fatalln("error:", err)
			return
		}
		output := uint8Array.New(outputBuffer.Len())
		js.CopyBytesToJS(output, outputBuffer.Bytes())
		x.Set("output", output)
		x.Set("sign", hex.EncodeToString(sign))
		x.Set("__out__", true)
	}
}
