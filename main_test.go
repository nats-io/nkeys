// Copyright 2018 The NATS Authors
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

package nkeys

import (
	"bytes"
	"crypto/rand"
	"io"
	"strings"
	"testing"

	"golang.org/x/crypto/ed25519"
)

func TestEncode(t *testing.T) {
	var rawKey [32]byte

	_, err := io.ReadFull(rand.Reader, rawKey[:])
	if err != nil {
		t.Fatalf("Unexpected error reading from crypto/rand: %v\n", err)
	}
	_, err = Encode(PrefixByteUser, rawKey[:])
	if err != nil {
		t.Fatalf("Unexpected error from Encode: %v\n", err)
	}
	str, err := Encode(22<<3, rawKey[:])
	if err == nil {
		t.Fatal("Expected an error from Encode but received nil\n")
	}
	if str != "" {
		t.Fatalf("Expected empty string from Encode: got %s\n", str)
	}
}

func TestDecode(t *testing.T) {
	var rawKey [32]byte

	_, err := io.ReadFull(rand.Reader, rawKey[:])
	if err != nil {
		t.Fatalf("Unexpected error reading from crypto/rand: %v\n", err)
	}
	str, err := Encode(PrefixByteUser, rawKey[:])
	if err != nil {
		t.Fatalf("Unexpected error from Encode: %v\n", err)
	}

	decoded, err := Decode(PrefixByteUser, str)
	if err != nil {
		t.Fatalf("Unexpected error from Decode: %v\n", err)
	}
	if !bytes.Equal(decoded, rawKey[:]) {
		t.Fatalf("Decoded does not match the original\n")
	}
}

func TestSeed(t *testing.T) {
	var rawKeyShort [32]byte

	_, err := io.ReadFull(rand.Reader, rawKeyShort[:])
	if err != nil {
		t.Fatalf("Unexpected error reading from crypto/rand: %v\n", err)
	}
	// Seeds need to be 64 bytes
	if _, err := EncodeSeed(PrefixByteUser, rawKeyShort[:]); err != ErrInvalidSeedLen {
		t.Fatalf("Did not receive ErrInvalidSeed error, received %v\n", err)
	}
	// Seeds need to be typed with only public types.
	if _, err := EncodeSeed(PrefixByteSeed, rawKeyShort[:]); err != ErrInvalidPrefixByte {
		t.Fatalf("Did not receive ErrInvalidPrefixByte error, received %v\n", err)
	}

	var rawSeed [64]byte

	_, err = io.ReadFull(rand.Reader, rawSeed[:])
	if err != nil {
		t.Fatalf("Unexpected error reading from crypto/rand: %v\n", err)
	}

	seed, err := EncodeSeed(PrefixByteUser, rawSeed[:])
	if err != nil {
		t.Fatalf("EncodeSeed received an error: %v\n", err)
	}

	pre, decoded, err := DecodeSeed(seed)
	if err != nil {
		t.Fatalf("Got an unexpected error from DecodeSeed: %v\n", err)
	}
	if pre != PrefixByteUser {
		t.Fatalf("Expected the prefix to be PrefixByteUser(%v), got %v\n",
			PrefixByteUser, pre)
	}
	if !bytes.Equal(decoded, rawSeed[:]) {
		t.Fatalf("Decoded seed does not match the original\n")
	}
}

func TestAccount(t *testing.T) {
	account, err := CreateAccount(nil)
	if err != nil {
		t.Fatalf("Expected non-nil error on CreateAccount, received %v\n", err)
	}
	if account == nil {
		t.Fatal("Expect a non-nil account\n")
	}
	seed, err := account.Seed()
	if err != nil {
		t.Fatalf("Unexpected error retrieving seed: %v\n", err)
	}
	_, err = Decode(PrefixByteSeed, seed)
	if err != nil {
		t.Fatalf("Expected a proper seed string, got %s\n", seed)
	}

	// Check Public
	public, err := account.PublicKey()
	if err != nil {
		t.Fatalf("Received an error retrieving public key: %v\n", err)
	}
	if public[0] != 'A' {
		t.Fatalf("Expected a prefix of 'A' but got %c\n", public[0])
	}

	// Check Private
	private, err := account.PrivateKey()
	if err != nil {
		t.Fatalf("Received an error retrieving private key: %v\n", err)
	}
	if private[0] != 'P' {
		t.Fatalf("Expected a prefix of 'P' but got %v\n", private[0])
	}

	// Check Sign and Verify
	data := []byte("Hello World")
	sig, err := account.Sign(data)
	if err != nil {
		t.Fatalf("Unexpected error signing from account: %v\n", err)
	}
	if len(sig) != ed25519.SignatureSize {
		t.Fatalf("Expected signature size of %d but got %d\n",
			ed25519.SignatureSize, len(sig))
	}
	err = account.Verify(data, sig)
	if err != nil {
		t.Fatalf("Unexpected error verifying signature: %v\n", err)
	}
}

func TestUser(t *testing.T) {
	user, err := CreateUser(nil)
	if err != nil {
		t.Fatalf("Expected non-nil error on CreateUser, received %v\n", err)
	}
	if user == nil {
		t.Fatal("Expect a non-nil user\n")
	}

	// Check Public
	public, err := user.PublicKey()
	if err != nil {
		t.Fatalf("Received an error retrieving public key: %v\n", err)
	}
	if public[0] != 'U' {
		t.Fatalf("Expected a prefix of 'U' but got %c\n", public[0])
	}
}

func TestCluster(t *testing.T) {
	cluster, err := CreateCluster(nil)
	if err != nil {
		t.Fatalf("Expected non-nil error on CreateCluster, received %v\n", err)
	}
	if cluster == nil {
		t.Fatal("Expect a non-nil cluster\n")
	}

	// Check Public
	public, err := cluster.PublicKey()
	if err != nil {
		t.Fatalf("Received an error retrieving public key: %v\n", err)
	}
	if public[0] != 'C' {
		t.Fatalf("Expected a prefix of 'C' but got %c\n", public[0])
	}
}

func TestServer(t *testing.T) {
	server, err := CreateServer(nil)
	if err != nil {
		t.Fatalf("Expected non-nil error on CreateServer, received %v\n", err)
	}
	if server == nil {
		t.Fatal("Expect a non-nil server\n")
	}

	// Check Public
	public, err := server.PublicKey()
	if err != nil {
		t.Fatalf("Received an error retrieving public key: %v\n", err)
	}
	if public[0] != 'N' {
		t.Fatalf("Expected a prefix of 'N' but got %c\n", public[0])
	}
}

func TestFromPublic(t *testing.T) {
	// Create a User
	user, err := CreateUser(nil)
	if err != nil {
		t.Fatalf("Expected non-nil error on CreateUser, received %v\n", err)
	}
	if user == nil {
		t.Fatal("Expect a non-nil user\n")
	}

	// Now create a publickey only KeyPair
	publicKey, err := user.PublicKey()
	if err != nil {
		t.Fatalf("Error retrieving public key from user: %v\n", err)
	}

	pubUser, err := FromPublicKey(publicKey)
	if err != nil {
		t.Fatalf("Error creating public key only user: %v\n", err)
	}

	pubUser, err = FromPublicKey(publicKey)
	if err != nil {
		t.Fatalf("Error creating public key only user: %v\n", err)
	}

	publicKey2, err := pubUser.PublicKey()
	if err != nil {
		t.Fatalf("Error retrieving public key from public user: %v\n", err)
	}
	// Make sure they match
	if strings.Compare(publicKey2, publicKey) != 0 {
		t.Fatalf("Expected the public keys to match\n")
	}

	if _, err = pubUser.PrivateKey(); err == nil {
		t.Fatalf("Expected and error trying to get private key\n")
	}
	if _, err := pubUser.Seed(); err == nil {
		t.Fatalf("Expected and error trying to get seed\n")
	}

	data := []byte("Hello World")

	// Can't sign..
	if _, err = pubUser.Sign(data); err != ErrCannotSign {
		t.Fatalf("Expected %v, but got %v\n", ErrCannotSign, err)
	}

	// Should be able to verify with pubUser.
	sig, err := user.Sign(data)
	if err != nil {
		t.Fatalf("Unexpected error signing from user: %v\n", err)
	}

	err = pubUser.Verify(data, sig)
	if err != nil {
		t.Fatalf("Unexpected error verifying signature: %v\n", err)
	}

	// Create another user to sign and make sure verify fails.
	user2, _ := CreateUser(nil)
	sig, _ = user2.Sign(data)

	err = pubUser.Verify(data, sig)
	if err == nil {
		t.Fatalf("Expected verification to fail.\n")
	}

	badUser := &pub{"USERBAD"}
	err = badUser.Verify(data, sig)
	if err == nil {
		t.Fatalf("Expected verification to fail.\n")
	}
}

func TestFromSeed(t *testing.T) {
	account, err := CreateAccount(nil)
	if err != nil {
		t.Fatalf("Expected non-nil error on CreateAccount, received %v\n", err)
	}
	if account == nil {
		t.Fatal("Expect a non-nil account\n")
	}

	data := []byte("Hello World")
	sig, err := account.Sign(data)
	if err != nil {
		t.Fatalf("Unexpected error signing from account: %v\n", err)
	}

	seed, err := account.Seed()
	if err != nil {
		t.Fatalf("Unexpected error retrieving seed: %v\n", err)
	}
	// Make sure the seed starts with SA
	if !strings.HasPrefix(seed, "SA") {
		t.Fatalf("Expected seed to start with 'SA', go '%s'\n", seed[:2])
	}

	account2, err := FromSeed(seed)
	if err != nil {
		t.Fatalf("Error recreating account from seed: %v\n", err)
	}
	if account2 == nil {
		t.Fatal("Expect a non-nil account\n")
	}
	err = account2.Verify(data, sig)
	if err != nil {
		t.Fatalf("Unexpected error verifying signature: %v\n", err)
	}
}

func TestKeyPairFailures(t *testing.T) {
	var tooshort [8]byte
	if _, err := createPair(bytes.NewReader(tooshort[:]), PrefixByteUser); err == nil {
		t.Fatal("Expected an error with insufficient rand\n")
	}

	if _, err := createPair(nil, PrefixBytePrivate); err == nil {
		t.Fatal("Expected an error with non-public prefix\n")
	}
	kpbad := &kp{"SEEDBAD"}
	if _, _, err := kpbad.keys(); err == nil {
		t.Fatal("Expected an error decoding keys with a bad seed\n")
	}
	if _, err := kpbad.PublicKey(); err == nil {
		t.Fatal("Expected an error getting PublicKey from KP with a bad seed\n")
	}
	if _, err := kpbad.PrivateKey(); err == nil {
		t.Fatal("Expected an error getting PrivateKey from KP with a bad seed\n")
	}
	if _, err := kpbad.Sign([]byte("ok")); err == nil {
		t.Fatal("Expected an error from Signing from KP with a bad seed\n")
	}
}

func TestBadDecode(t *testing.T) {
	if _, err := decode("foo!"); err == nil {
		t.Fatal("Expected an error decoding non-base32\n")
	}
	if _, err := decode("OK"); err == nil {
		t.Fatal("Expected an error decoding a too short string\n")
	}

	// Create invalid checksum
	account, _ := CreateAccount(nil)
	pkey, _ := account.PublicKey()
	bpkey := []byte(pkey)
	bpkey[len(pkey)-1] = '0'
	bpkey[len(pkey)-2] = '0'
	if _, err := decode(string(bpkey)); err == nil {
		t.Fatal("Expected error on decode with bad checksum\n")
	}

	if _, err := Decode(PrefixByteUser, pkey); err == nil {
		t.Fatal("Expected error on Decode with mismatched prefix\n")
	}
	if _, err := Decode(PrefixByte(3<<3), pkey); err == nil {
		t.Fatal("Expected error on Decode with invalid prefix\n")
	}
	if _, err := Decode(PrefixByteAccount, string(bpkey)); err == nil {
		t.Fatal("Expected error on Decode with bad checksum\n")
	}
	// Seed version
	if _, _, err := DecodeSeed(string(bpkey)); err == nil {
		t.Fatal("Expected error on DecodeSeed with bad checksum\n")
	}
	if _, _, err := DecodeSeed(pkey); err == nil {
		t.Fatal("Expected error on DecodeSeed with bad seed type\n")
	}

	seed, _ := account.Seed()
	bseed := []byte(seed)
	bseed[1] = 'S'
	if _, _, err := DecodeSeed(string(bseed)); err == nil {
		t.Fatal("Expected error on DecodeSeed with bad prefix type\n")
	}
	if _, err := FromSeed(string(bseed)); err == nil {
		t.Fatal("Expected error on FromSeed with bad prefix type\n")
	}

	if _, err := FromPublicKey(string(bpkey)); err == nil {
		t.Fatal("Expected error on FromPublicKey with bad checksum\n")
	}
	if _, err := FromPublicKey(seed); err == nil {
		t.Fatal("Expected error on FromPublicKey with bad checksum\n")
	}
}
