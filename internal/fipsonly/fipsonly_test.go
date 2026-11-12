// Copyright 2026 The NATS Authors
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

//go:debug fips140=only

// Package fipsonly runs the nkeys Ed25519 operations in FIPS 140-3 only mode.
//
// The //go:debug directive above sets GODEBUG=fips140=only for this package's
// test binary alone. The tests live in their own package because the directive
// applies to the whole test binary, and curve (xkey) operations are not FIPS
// 140-3 approved, so they cannot run in this mode.
//
// Build with GOFIPS140 (for example GOFIPS140=certified) to run these tests
// against a frozen Go Cryptographic Module instead of the toolchain's own.
package fipsonly

import (
	"bytes"
	"crypto/fips140"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
	"testing"

	"github.com/nats-io/nkeys"
)

var ed25519Prefixes = []nkeys.PrefixByte{
	nkeys.PrefixByteOperator,
	nkeys.PrefixByteAccount,
	nkeys.PrefixByteUser,
	nkeys.PrefixByteServer,
	nkeys.PrefixByteCluster,
}

func TestFIPSModeEnabled(t *testing.T) {
	if !fips140.Enabled() {
		t.Fatal("FIPS 140-3 mode is not enabled: the //go:debug fips140=only directive did not apply")
	}
}

// TestKnownAnswer derives key pairs from the first Ed25519 test vector in
// RFC 8032, section 7.1, and checks the public key and signature.
func TestKnownAnswer(t *testing.T) {
	seed := mustDecodeHex(t, "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
	public := mustDecodeHex(t, "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
	signature := mustDecodeHex(t, "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b")

	for _, prefix := range ed25519Prefixes {
		t.Run(prefix.String(), func(t *testing.T) {
			kp, err := nkeys.FromRawSeed(prefix, seed)
			if err != nil {
				t.Fatal(err)
			}
			want, err := nkeys.Encode(prefix, public)
			if err != nil {
				t.Fatal(err)
			}
			got, err := kp.PublicKey()
			if err != nil {
				t.Fatal(err)
			}
			if got != string(want) {
				t.Fatalf("PublicKey() = %q, want %q", got, want)
			}
			sig, err := kp.Sign(nil)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(sig, signature) {
				t.Fatalf("Sign(nil) = %x, want %x", sig, signature)
			}
		})
	}
}

// TestKeyPairLifecycle creates key pairs, which draws on crypto/rand and is
// allowed in FIPS-only mode, then exercises every operation on a key pair
// restored from the encoded seed.
func TestKeyPairLifecycle(t *testing.T) {
	msg := []byte("nkeys in fips140=only mode")
	for _, prefix := range ed25519Prefixes {
		t.Run(prefix.String(), func(t *testing.T) {
			created, err := nkeys.CreatePair(prefix)
			if err != nil {
				t.Fatal(err)
			}
			seed, err := created.Seed()
			if err != nil {
				t.Fatal(err)
			}
			kp, err := nkeys.FromSeed(seed)
			if err != nil {
				t.Fatal(err)
			}

			pub, err := kp.PublicKey()
			if err != nil {
				t.Fatal(err)
			}
			if got := nkeys.Prefix(pub); got != prefix {
				t.Fatalf("public key prefix = %v, want %v", got, prefix)
			}
			if want, err := created.PublicKey(); err != nil || pub != want {
				t.Fatalf("restored public key = %q, want %q (err %v)", pub, want, err)
			}

			priv, err := kp.PrivateKey()
			if err != nil {
				t.Fatal(err)
			}
			if got := nkeys.Prefix(string(priv)); got != nkeys.PrefixBytePrivate {
				t.Fatalf("private key prefix = %v, want %v", got, nkeys.PrefixBytePrivate)
			}

			sig, err := kp.Sign(msg)
			if err != nil {
				t.Fatal(err)
			}
			if err := kp.Verify(msg, sig); err != nil {
				t.Fatalf("Verify with key pair: %v", err)
			}
			pkp, err := nkeys.FromPublicKey(pub)
			if err != nil {
				t.Fatal(err)
			}
			if err := pkp.Verify(msg, sig); err != nil {
				t.Fatalf("Verify with public key: %v", err)
			}
			sig[0] ^= 0xff
			if err := pkp.Verify(msg, sig); !errors.Is(err, nkeys.ErrInvalidSignature) {
				t.Fatalf("Verify of a tampered signature = %v, want %v", err, nkeys.ErrInvalidSignature)
			}
		})
	}
}

// TestCreatePairWithApprovedRandom checks the readers that CreatePairWithRand
// accepts in FIPS-only mode: nil and crypto/rand.Reader itself.
func TestCreatePairWithApprovedRandom(t *testing.T) {
	readers := []struct {
		name string
		rr   io.Reader
	}{
		{"nil", nil},
		{"rand.Reader", rand.Reader},
	}
	for _, prefix := range ed25519Prefixes {
		t.Run(prefix.String(), func(t *testing.T) {
			for _, r := range readers {
				t.Run(r.name, func(t *testing.T) {
					kp, err := nkeys.CreatePairWithRand(prefix, r.rr)
					if err != nil {
						t.Fatal(err)
					}
					pub, err := kp.PublicKey()
					if err != nil {
						t.Fatal(err)
					}
					if got := nkeys.Prefix(pub); got != prefix {
						t.Fatalf("public key prefix = %v, want %v", got, prefix)
					}
				})
			}
		})
	}
}

func mustDecodeHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
