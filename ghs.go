package main

import (
	"bytes"
	"encoding/hex"
	"log"
	"os"
	"syscall/js"

	"github.com/jamesliu96/geheim"
)

func main() {
	log.Println("#run")
	defer log.Println("#exit")
	global := js.Global()
	uint8Array := global.Get("Uint8Array")
	x := global.Get("__x__")
	x.Set("__out__", false)
	if !x.Get("__init__").Truthy() {
		log.Println("init")
		x.Set("CipherString", geheim.GetCipherString())
		x.Set("DefaultCipher", int(geheim.DefaultCipher))
		x.Set("CipherDesc", geheim.CipherDesc)
		x.Set("ModeString", geheim.GetModeString())
		x.Set("DefaultMode", int(geheim.DefaultMode))
		x.Set("ModeDesc", geheim.ModeDesc)
		x.Set("KDFString", geheim.GetKDFString())
		x.Set("DefaultKDF", int(geheim.DefaultKDF))
		x.Set("KDFDesc", geheim.KDFDesc)
		x.Set("MACString", geheim.GetMACString())
		x.Set("DefaultMAC", int(geheim.DefaultMAC))
		x.Set("MACDesc", geheim.MACDesc)
		x.Set("MDString", geheim.GetMDString())
		x.Set("DefaultMD", int(geheim.DefaultMD))
		x.Set("MDDesc", geheim.MDDesc)
		x.Set("MinSec", geheim.MinSec)
		x.Set("MaxSec", geheim.MaxSec)
		x.Set("DefaultSec", geheim.DefaultSec)
		x.Set("SecDesc", geheim.SecDesc)
		x.Set("__init__", true)
		return
	}
	input := x.Get("input")
	if !input.Truthy() {
		log.Fatalln("error:", "no input")
		return
	}
	pass := x.Get("pass")
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
		sign, err := geheim.DecryptVerify(inputBuffer, outputBuffer, []byte(pass.String()), signexBytes, geheim.NewPrintFunc(os.Stdout))
		if err != nil {
			log.Fatalln("error:", err)
			return
		}
		x.Set("sign", hex.EncodeToString(sign))
	} else {
		sign, err := geheim.Encrypt(inputBuffer, outputBuffer, []byte(pass.String()), geheim.Cipher(x.Get("cipher").Int()), geheim.Mode(x.Get("mode").Int()), geheim.KDF(x.Get("kdf").Int()), geheim.MAC(x.Get("mac").Int()), geheim.MD(x.Get("md").Int()), x.Get("sec").Int(), geheim.NewPrintFunc(os.Stdout))
		if err != nil {
			log.Fatalln("error:", err)
			return
		}
		x.Set("sign", hex.EncodeToString(sign))
	}
	output := uint8Array.New(outputBuffer.Len())
	js.CopyBytesToJS(output, outputBuffer.Bytes())
	x.Set("output", output)
	x.Set("__out__", true)
}
