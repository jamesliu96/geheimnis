package main

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"log"
	"math"
	"syscall/js"

	"github.com/jamesliu96/geheim"
)

func formatSize(n int64) string {
	var unit string
	nn := float64(n)
	f := "%.2f"
	switch {
	case n >= 1<<60:
		nn /= 1 << 60
		unit = "E"
	case n >= 1<<50:
		nn /= 1 << 50
		unit = "P"
	case n >= 1<<40:
		nn /= 1 << 40
		unit = "T"
	case n >= 1<<30:
		nn /= 1 << 30
		unit = "G"
	case n >= 1<<20:
		nn /= 1 << 20
		unit = "M"
	case n >= 1<<10:
		nn /= 1 << 10
		unit = "K"
	default:
		f = "%.f"
	}
	return fmt.Sprintf("%s%sB", fmt.Sprintf(f, math.Max(0, nn)), unit)
}

var dbg geheim.PrintFunc = func(version int, cipher geheim.Cipher, mode geheim.Mode, kdf geheim.KDF, mac geheim.MAC, md geheim.MD, sec int, pass, salt, iv, key []byte) error {
	fmt.Printf("%-8s%d\n", "VERSION", version)
	fmt.Printf("%-8s%s(%d)\n", "CIPHER", geheim.CipherNames[cipher], cipher)
	if cipher == geheim.AES {
		fmt.Printf("%-8s%s(%d)\n", "MODE", geheim.ModeNames[mode], mode)
	}
	fmt.Printf("%-8s%s(%d)\n", "KDF", geheim.KDFNames[kdf], kdf)
	fmt.Printf("%-8s%s(%d)\n", "MAC", geheim.MACNames[mac], mac)
	if kdf == geheim.PBKDF2 || mac == geheim.HMAC {
		fmt.Printf("%-8s%s(%d)\n", "MD", geheim.MDNames[md], md)
	}
	iter, memory, sec := geheim.GetSecIterMemory(sec)
	if kdf == geheim.PBKDF2 {
		fmt.Printf("%-8s%d(%d)\n", "SEC", sec, iter)
	} else {
		fmt.Printf("%-8s%d(%s)\n", "SEC", sec, formatSize(int64(memory)))
	}
	fmt.Printf("%-8s%s(%x)\n", "PASS", pass, pass)
	fmt.Printf("%-8s%x\n", "SALT", salt)
	fmt.Printf("%-8s%x\n", "IV", iv)
	fmt.Printf("%-8s%x\n", "KEY", key)
	return nil
}

func main() {
	log.Println("start")
	defer log.Println("end")
	global := js.Global()
	u8 := global.Get("Uint8Array")
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
		sign, err := geheim.DecryptVerify(inputBuffer, outputBuffer, []byte(pass.String()), signexBytes, dbg)
		if err != nil {
			log.Fatalln("error:", err)
			return
		}
		output := u8.New(outputBuffer.Len())
		js.CopyBytesToJS(output, outputBuffer.Bytes())
		x.Set("output", output)
		x.Set("sign", hex.EncodeToString(sign))
		x.Set("__out__", true)
	} else {
		sign, err := geheim.Encrypt(inputBuffer, outputBuffer, []byte(pass.String()), geheim.Cipher(x.Get("cipher").Int()), geheim.Mode(x.Get("mode").Int()), geheim.KDF(x.Get("kdf").Int()), geheim.MAC(x.Get("mac").Int()), geheim.MD(x.Get("md").Int()), x.Get("sec").Int(), dbg)
		if err != nil {
			log.Fatalln("error:", err)
			return
		}
		output := u8.New(outputBuffer.Len())
		js.CopyBytesToJS(output, outputBuffer.Bytes())
		x.Set("output", output)
		x.Set("sign", hex.EncodeToString(sign))
		x.Set("__out__", true)
	}
}
