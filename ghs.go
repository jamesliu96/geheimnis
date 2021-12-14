package main

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"math"
	"os"
	"reflect"
	"runtime"
	"strings"
	"syscall/js"

	"github.com/jamesliu96/geheim"
	"golang.org/x/sys/cpu"
)

const app = "ghs"

var gitTag = "*"
var gitRev = "*"

func getCPUFeatures() (d []string) {
	var v interface{}
	switch runtime.GOARCH {
	case "386":
		fallthrough
	case "amd64":
		v = cpu.X86
	case "arm":
		v = cpu.ARM
	case "arm64":
		v = cpu.ARM64
	case "mips64":
		fallthrough
	case "mips64le":
		v = cpu.MIPS64X
	case "ppc64":
		fallthrough
	case "ppc64le":
		v = cpu.PPC64
	case "s390x":
		v = cpu.S390X
	default:
		return
	}
	ks := reflect.TypeOf(v)
	vs := reflect.ValueOf(v)
	for i := 0; i < ks.NumField(); i++ {
		k := ks.Field(i)
		v := vs.Field(i)
		if k.Type.Kind() == reflect.Bool && v.Bool() {
			name := strings.TrimPrefix(k.Name, "Has")
			if name == k.Name {
				name = strings.TrimPrefix(k.Name, "Is")
			}
			d = append(d, name)
		}
	}
	return
}

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

func printf(format string, v ...interface{}) {
	fmt.Fprintf(os.Stderr, format, v...)
}

var dbg geheim.PrintFunc = func(version int, cipher geheim.Cipher, mode geheim.Mode, kdf geheim.KDF, mac geheim.MAC, md geheim.MD, sec int, pass, salt, iv, key []byte) error {
	printf("%-8s%d\n", "VERSION", version)
	printf("%-8s%s(%d)\n", "CIPHER", geheim.CipherNames[cipher], cipher)
	if cipher == geheim.AES {
		printf("%-8s%s(%d)\n", "MODE", geheim.ModeNames[mode], mode)
	}
	printf("%-8s%s(%d)\n", "KDF", geheim.KDFNames[kdf], kdf)
	printf("%-8s%s(%d)\n", "MAC", geheim.MACNames[mac], mac)
	if kdf == geheim.PBKDF2 || mac == geheim.HMAC {
		printf("%-8s%s(%d)\n", "MD", geheim.MDNames[md], md)
	}
	iter, memory := geheim.GetSecIterMemory(sec)
	if kdf == geheim.PBKDF2 {
		printf("%-8s%d(%d)\n", "SEC", sec, iter)
	} else {
		printf("%-8s%d(%s)\n", "SEC", sec, formatSize(int64(memory)))
	}
	printf("%-8s%s(%x)\n", "PASS", pass, pass)
	printf("%-8s%x\n", "SALT", salt)
	printf("%-8s%x\n", "IV", iv)
	printf("%-8s%x\n", "KEY", key)
	return nil
}

func main() {
	printf("%s [%s-%s] %s (%s) %s\n", app, runtime.GOOS, runtime.GOARCH, gitTag, gitRev, getCPUFeatures())
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
	if !input.Truthy() || !pass.Truthy() {
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
				printf("%e", err)
				return
			}
		}
		sign, err := geheim.DecryptVerify(inputBuffer, outputBuffer, []byte(pass.String()), signexBytes, dbg)
		if err != nil {
			printf("%e", err)
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
			printf("%e", err)
			return
		}
		output := u8.New(outputBuffer.Len())
		js.CopyBytesToJS(output, outputBuffer.Bytes())
		x.Set("output", output)
		x.Set("sign", hex.EncodeToString(sign))
		x.Set("__out__", true)
	}
}
