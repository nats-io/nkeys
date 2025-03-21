// Copyright 2018-2023 The NATS Authors
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"bytes"
	"crypto/rand"
	"encoding/base32"
	"encoding/base64"
	"flag"
	"fmt"
	"log"
	"os"
	"runtime"
	"strings"

	"github.com/nats-io/nkeys"
)

// this will be set during compilation when a release is made on tools
var Version string

const defaultVanMax = 10_000_000

func usage() {
	log.Fatalf(`Usage: nk [options]
    -v                    Show version
    -gen <type>           Generate key for [user|account|server|cluster|operator|curve|x25519]
    -sign <file>          Sign <file> with -inkey <keyfile>
    -verify <file>        Verify <file> with -inkey <keyfile> or -pubin <public> and -sigfile <file>
    -inkey <file>         Input key file (seed/private key)
    -pubin <file>         Public key file
    -sigfile <file>       Signature file
    -pubout               Output public key
    -e                    Entropy file, e.g. /dev/urandom
    -pre <vanity>         Attempt to generate public key given prefix, e.g. nk -gen user -pre derek
    -maxpre <N>           Maximum attempts at generating the correct key prefix, default is 10,000,000
`)
}

type KeyPair interface {
	Seed() ([]byte, error)
	PublicKey() (string, error)
}

func main() {
	var entropy = flag.String("e", "", "Entropy file, e.g. /dev/urandom")
	var keyFile = flag.String("inkey", "", "Input key file (seed/private key)")
	var pubFile = flag.String("pubin", "", "Public key file")

	var signFile = flag.String("sign", "", "Sign <file> with -inkey <keyfile>")
	var sigFile = flag.String("sigfile", "", "Signature file")

	var verifyFile = flag.String("verify", "", "Verify <file> with -inkey <keyfile> or -pubin <public> and -sigfile <file>")

	var keyType = flag.String("gen", "", "Generate key for <type>, e.g. nk -gen user")
	var pubout = flag.Bool("pubout", false, "Output public key")

	var version = flag.Bool("v", false, "Show version")
	var vanPre = flag.String("pre", "", "Attempt to generate public key given prefix, e.g. nk -gen user -pre derek")
	var vanMax = flag.Int("maxpre", defaultVanMax, "Maximum attempts at generating the correct key prefix")

	log.SetFlags(0)
	log.SetOutput(os.Stdout)

	flag.Usage = usage
	flag.Parse()

	if *version {
		fmt.Printf("nk version %s\n", Version)
		return
	}

	// Create Key
	if *keyType != "" {
		var kp KeyPair
		// Check to see if we are trying to do a vanity public key.
		if *vanPre != "" {
			kp = createVanityKey(*keyType, *vanPre, *entropy, *vanMax)
		} else {
			kp = genKeyPair(preForType(*keyType), *entropy)
		}
		seed, err := kp.Seed()
		if err != nil {
			log.Fatal(err)
		}
		log.Printf("%s", seed)
		if *pubout || *vanPre != "" {
			pub, _ := kp.PublicKey()
			log.Printf("%s", pub)
		}
		return

	}

	if *entropy != "" {
		log.Fatalf("Entropy file only used when creating keys with -gen")
	}

	// Sign
	if *signFile != "" {
		sign(*signFile, *keyFile)
		return
	}

	// Verify
	if *verifyFile != "" {
		verify(*verifyFile, *keyFile, *pubFile, *sigFile)
		return
	}

	// Show public key from seed/private
	if *keyFile != "" && *pubout {
		printPublicFromSeed(*keyFile)
		return
	}

	usage()
}

func printPublicFromSeed(keyFile string) {
	seed := readKeyFile(keyFile)
	kp, err := nkeys.FromSeed(seed)
	if err != nil {
		log.Fatal(err)
	}
	pub, _ := kp.PublicKey()
	log.Printf("%s", pub)
}

func sign(fname, keyFile string) {
	if keyFile == "" {
		log.Fatalf("Sign requires a seed/private key via -inkey <file>")
	}
	seed := readKeyFile(keyFile)
	kp, err := nkeys.FromSeed(seed)
	if err != nil {
		log.Fatal(err)
	}

	content, err := os.ReadFile(fname)
	if err != nil {
		log.Fatal(err)
	}

	sigraw, err := kp.Sign(content)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("%s", base64.RawURLEncoding.EncodeToString(sigraw))
}

func verify(fname, keyFile, pubFile, sigFile string) {
	if keyFile == "" && pubFile == "" {
		log.Fatalf("Verify requires a seed key via -inkey or a public key via -pubin")
	}
	if sigFile == "" {
		log.Fatalf("Verify requires a signature via -sigfile")
	}
	var err error
	var kp nkeys.KeyPair
	if keyFile != "" {
		seed := readKeyFile(keyFile)
		kp, err = nkeys.FromSeed(seed)
	} else {
		// Public Key
		public := readKeyFile(pubFile)
		kp, err = nkeys.FromPublicKey(string(public))
	}
	if err != nil {
		log.Fatal(err)
	}

	content, err := os.ReadFile(fname)
	if err != nil {
		log.Fatal(err)
	}

	sigEnc, err := os.ReadFile(sigFile)
	if err != nil {
		log.Fatal(err)
	}
	sig, err := base64.RawURLEncoding.DecodeString(string(sigEnc))
	if err != nil {
		log.Fatal(err)
	}
	if err := kp.Verify(content, sig); err != nil {
		log.Fatal(err)
	}
	log.Printf("Verified OK")
}

func preForType(keyType string) nkeys.PrefixByte {
	keyType = strings.ToLower(keyType)
	switch keyType {
	case "user":
		return nkeys.PrefixByteUser
	case "account":
		return nkeys.PrefixByteAccount
	case "server":
		return nkeys.PrefixByteServer
	case "cluster":
		return nkeys.PrefixByteCluster
	case "operator":
		return nkeys.PrefixByteOperator
	case "curve", "x25519":
		return nkeys.PrefixByteCurve

	default:
		log.Fatalf("Usage: nk -gen [user|account|server|cluster|operator|curve|x25519]\n")
	}
	return nkeys.PrefixByte(0)
}

func genKeyPair(pre nkeys.PrefixByte, entropy string) KeyPair {
	// See if we override entropy.
	ef := rand.Reader
	if entropy != "" {
		r, err := os.Open(entropy)
		if err != nil {
			log.Fatal(err)
		}
		ef = r
	}

	var kp KeyPair
	var err error

	if pre == nkeys.PrefixByteCurve {
		kp, err = nkeys.CreateCurveKeysWithRand(ef)
		if err != nil {
			log.Fatalf("Error creating %c: %v", pre, err)
		}
	} else {
		kp, err = nkeys.CreatePairWithRand(pre, ef)
		if err != nil {
			log.Fatalf("Error creating %c: %v", pre, err)
		}
	}
	return kp
}

var b32Enc = base32.StdEncoding.WithPadding(base32.NoPadding)

func createVanityKey(keyType, vanity, entropy string, max int) KeyPair {
	spinners := []rune(`⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏`)
	pre := preForType(keyType)
	vanity = strings.ToUpper(vanity)
	// Check to make sure we can base32 into it by trying to decode it.
	_, err := b32Enc.DecodeString(vanity)
	if err != nil {
		log.Fatalf("Can not generate base32 encoded strings to match '%s'", vanity)
	}

	ncpu := runtime.NumCPU()

	// Work channel
	wch := make(chan struct{})
	defer close(wch)

	// Found solution
	found := make(chan KeyPair)

	// Start NumCPU go routines.
	for i := 0; i < ncpu; i++ {
		go func() {
			for range wch {
				kp := genKeyPair(pre, entropy)
				pub, _ := kp.PublicKey()
				if strings.HasPrefix(pub[1:], vanity) {
					found <- kp
					return
				}
			}
		}()
	}

	// Run through max iterations.
	for i := 0; i < max; i++ {
		spin := spinners[i%len(spinners)]
		fmt.Fprintf(os.Stderr, "\r\033[mcomputing\033[m %s ", string(spin))
		wch <- struct{}{}
		select {
		case kp := <-found:
			fmt.Fprintf(os.Stderr, "\r")
			return kp
		default:
		}
	}

	fmt.Fprintf(os.Stderr, "\r")
	log.Fatalf("Failed to generate prefix after %d attempts", max)
	return nil
}

func readKeyFile(filename string) []byte {
	var key []byte
	contents, err := os.ReadFile(filename)
	if err != nil {
		log.Fatal(err)
	}
	defer wipeSlice(contents)

	lines := bytes.Split(contents, []byte("\n"))
	for _, line := range lines {
		if nkeys.IsValidEncoding(line) {
			key = make([]byte, len(line))
			copy(key, line)
			return key
		}
	}
	if key == nil {
		log.Fatalf("Could not find a valid key")
	}
	return key
}

func wipeSlice(buf []byte) {
	for i := range buf {
		buf[i] = 'x'
	}
}
