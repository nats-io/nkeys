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
		t.Fatalf("Unexpected error reading from crypto/rand: %v", err)
	}
	_, err = Encode(PrefixByteUser, rawKey[:])
	if err != nil {
		t.Fatalf("Unexpected error from Encode: %v", err)
	}
	str, err := Encode(22<<3, rawKey[:])
	if err == nil {
		t.Fatal("Expected an error from Encode but received nil")
	}
	if str != "" {
		t.Fatalf("Expected empty string from Encode: got %s", str)
	}
}

func TestDecode(t *testing.T) {
	var rawKey [32]byte

	_, err := io.ReadFull(rand.Reader, rawKey[:])
	if err != nil {
		t.Fatalf("Unexpected error reading from crypto/rand: %v", err)
	}
	str, err := Encode(PrefixByteUser, rawKey[:])
	if err != nil {
		t.Fatalf("Unexpected error from Encode: %v", err)
	}

	decoded, err := Decode(PrefixByteUser, str)
	if err != nil {
		t.Fatalf("Unexpected error from Decode: %v", err)
	}
	if !bytes.Equal(decoded, rawKey[:]) {
		t.Fatalf("Decoded does not match the original")
	}
}

func TestSeed(t *testing.T) {
	var rawKeyShort [32]byte

	_, err := io.ReadFull(rand.Reader, rawKeyShort[:])
	if err != nil {
		t.Fatalf("Unexpected error reading from crypto/rand: %v", err)
	}
	// Seeds need to be 64 bytes
	if _, err := EncodeSeed(PrefixByteUser, rawKeyShort[:]); err != ErrInvalidSeedLen {
		t.Fatalf("Did not receive ErrInvalidSeed error, received %v", err)
	}
	// Seeds need to be typed with only public types.
	if _, err := EncodeSeed(PrefixByteSeed, rawKeyShort[:]); err != ErrInvalidPrefixByte {
		t.Fatalf("Did not receive ErrInvalidPrefixByte error, received %v", err)
	}

	var rawSeed [64]byte

	_, err = io.ReadFull(rand.Reader, rawSeed[:])
	if err != nil {
		t.Fatalf("Unexpected error reading from crypto/rand: %v", err)
	}

	seed, err := EncodeSeed(PrefixByteUser, rawSeed[:])
	if err != nil {
		t.Fatalf("EncodeSeed received an error: %v", err)
	}

	pre, decoded, err := DecodeSeed(seed)
	if err != nil {
		t.Fatalf("Got an unexpected error from DecodeSeed: %v", err)
	}
	if pre != PrefixByteUser {
		t.Fatalf("Expected the prefix to be PrefixByteUser(%v), got %v",
			PrefixByteUser, pre)
	}
	if !bytes.Equal(decoded, rawSeed[:]) {
		t.Fatalf("Decoded seed does not match the original")
	}
}

func TestAccount(t *testing.T) {
	account, err := CreateAccount(nil)
	if err != nil {
		t.Fatalf("Expected non-nil error on CreateAccount, received %v", err)
	}
	if account == nil {
		t.Fatal("Expect a non-nil account")
	}
	seed, err := account.Seed()
	if err != nil {
		t.Fatalf("Unexpected error retrieving seed: %v", err)
	}
	_, err = Decode(PrefixByteSeed, seed)
	if err != nil {
		t.Fatalf("Expected a proper seed string, got %s", seed)
	}

	// Check Public
	public, err := account.PublicKey()
	if err != nil {
		t.Fatalf("Received an error retrieving public key: %v", err)
	}
	if public[0] != 'A' {
		t.Fatalf("Expected a prefix of 'A' but got %c", public[0])
	}
	if !IsValidPublicAccountKey(public) {
		t.Fatalf("Not a valid public account key")
	}

	// Check Private
	private, err := account.PrivateKey()
	if err != nil {
		t.Fatalf("Received an error retrieving private key: %v", err)
	}
	if private[0] != 'P' {
		t.Fatalf("Expected a prefix of 'P' but got %v", private[0])
	}

	// Check Sign and Verify
	data := []byte("Hello World")
	sig, err := account.Sign(data)
	if err != nil {
		t.Fatalf("Unexpected error signing from account: %v", err)
	}
	if len(sig) != ed25519.SignatureSize {
		t.Fatalf("Expected signature size of %d but got %d",
			ed25519.SignatureSize, len(sig))
	}
	err = account.Verify(data, sig)
	if err != nil {
		t.Fatalf("Unexpected error verifying signature: %v", err)
	}
}

func TestUser(t *testing.T) {
	user, err := CreateUser(nil)
	if err != nil {
		t.Fatalf("Expected non-nil error on CreateUser, received %v", err)
	}
	if user == nil {
		t.Fatal("Expect a non-nil user")
	}

	// Check Public
	public, err := user.PublicKey()
	if err != nil {
		t.Fatalf("Received an error retrieving public key: %v", err)
	}
	if public[0] != 'U' {
		t.Fatalf("Expected a prefix of 'U' but got %c", public[0])
	}
	if !IsValidPublicUserKey(public) {
		t.Fatalf("Not a valid public user key")
	}
}

func TestCluster(t *testing.T) {
	cluster, err := CreateCluster(nil)
	if err != nil {
		t.Fatalf("Expected non-nil error on CreateCluster, received %v", err)
	}
	if cluster == nil {
		t.Fatal("Expect a non-nil cluster")
	}

	// Check Public
	public, err := cluster.PublicKey()
	if err != nil {
		t.Fatalf("Received an error retrieving public key: %v", err)
	}
	if public[0] != 'C' {
		t.Fatalf("Expected a prefix of 'C' but got %c", public[0])
	}
	if !IsValidPublicClusterKey(public) {
		t.Fatalf("Not a valid public cluster key")
	}
}

func TestServer(t *testing.T) {
	server, err := CreateServer(nil)
	if err != nil {
		t.Fatalf("Expected non-nil error on CreateServer, received %v", err)
	}
	if server == nil {
		t.Fatal("Expect a non-nil server")
	}

	// Check Public
	public, err := server.PublicKey()
	if err != nil {
		t.Fatalf("Received an error retrieving public key: %v", err)
	}
	if public[0] != 'N' {
		t.Fatalf("Expected a prefix of 'N' but got %c", public[0])
	}
	if !IsValidPublicServerKey(public) {
		t.Fatalf("Not a valid public server key")
	}
}

func TestFromPublic(t *testing.T) {
	// Create a User
	user, err := CreateUser(nil)
	if err != nil {
		t.Fatalf("Expected non-nil error on CreateUser, received %v", err)
	}
	if user == nil {
		t.Fatal("Expect a non-nil user")
	}

	// Now create a publickey only KeyPair
	publicKey, err := user.PublicKey()
	if err != nil {
		t.Fatalf("Error retrieving public key from user: %v", err)
	}

	pubUser, err := FromPublicKey(publicKey)
	if err != nil {
		t.Fatalf("Error creating public key only user: %v", err)
	}

	publicKey2, err := pubUser.PublicKey()
	if err != nil {
		t.Fatalf("Error retrieving public key from public user: %v", err)
	}
	// Make sure they match
	if strings.Compare(publicKey2, publicKey) != 0 {
		t.Fatalf("Expected the public keys to match")
	}

	if _, err = pubUser.PrivateKey(); err == nil {
		t.Fatalf("Expected and error trying to get private key")
	}
	if _, err := pubUser.Seed(); err == nil {
		t.Fatalf("Expected and error trying to get seed")
	}

	data := []byte("Hello World")

	// Can't sign..
	if _, err = pubUser.Sign(data); err != ErrCannotSign {
		t.Fatalf("Expected %v, but got %v", ErrCannotSign, err)
	}

	// Should be able to verify with pubUser.
	sig, err := user.Sign(data)
	if err != nil {
		t.Fatalf("Unexpected error signing from user: %v", err)
	}

	err = pubUser.Verify(data, sig)
	if err != nil {
		t.Fatalf("Unexpected error verifying signature: %v", err)
	}

	// Create another user to sign and make sure verify fails.
	user2, _ := CreateUser(nil)
	sig, _ = user2.Sign(data)

	err = pubUser.Verify(data, sig)
	if err == nil {
		t.Fatalf("Expected verification to fail.")
	}

	badUser := &pub{"USERBAD"}
	err = badUser.Verify(data, sig)
	if err == nil {
		t.Fatalf("Expected verification to fail.")
	}
}

func TestFromSeed(t *testing.T) {
	account, err := CreateAccount(nil)
	if err != nil {
		t.Fatalf("Expected non-nil error on CreateAccount, received %v", err)
	}
	if account == nil {
		t.Fatal("Expect a non-nil account")
	}

	data := []byte("Hello World")
	sig, err := account.Sign(data)
	if err != nil {
		t.Fatalf("Unexpected error signing from account: %v", err)
	}

	seed, err := account.Seed()
	if err != nil {
		t.Fatalf("Unexpected error retrieving seed: %v", err)
	}
	// Make sure the seed starts with SA
	if !strings.HasPrefix(seed, "SA") {
		t.Fatalf("Expected seed to start with 'SA', go '%s'", seed[:2])
	}

	account2, err := FromSeed(seed)
	if err != nil {
		t.Fatalf("Error recreating account from seed: %v", err)
	}
	if account2 == nil {
		t.Fatal("Expect a non-nil account")
	}
	err = account2.Verify(data, sig)
	if err != nil {
		t.Fatalf("Unexpected error verifying signature: %v", err)
	}
}

func TestKeyPairFailures(t *testing.T) {
	var tooshort [8]byte
	if _, err := createPair(bytes.NewReader(tooshort[:]), PrefixByteUser); err == nil {
		t.Fatal("Expected an error with insufficient rand")
	}

	if _, err := createPair(nil, PrefixBytePrivate); err == nil {
		t.Fatal("Expected an error with non-public prefix")
	}
	kpbad := &kp{"SEEDBAD"}
	if _, _, err := kpbad.keys(); err == nil {
		t.Fatal("Expected an error decoding keys with a bad seed")
	}
	if _, err := kpbad.PublicKey(); err == nil {
		t.Fatal("Expected an error getting PublicKey from KP with a bad seed")
	}
	if _, err := kpbad.PrivateKey(); err == nil {
		t.Fatal("Expected an error getting PrivateKey from KP with a bad seed")
	}
	if _, err := kpbad.Sign([]byte("ok")); err == nil {
		t.Fatal("Expected an error from Signing from KP with a bad seed")
	}
}

func TestBadDecode(t *testing.T) {
	if _, err := decode("foo!"); err == nil {
		t.Fatal("Expected an error decoding non-base32")
	}
	if _, err := decode("OK"); err == nil {
		t.Fatal("Expected an error decoding a too short string")
	}

	// Create invalid checksum
	account, _ := CreateAccount(nil)
	pkey, _ := account.PublicKey()
	bpkey := []byte(pkey)
	bpkey[len(pkey)-1] = '0'
	bpkey[len(pkey)-2] = '0'
	if _, err := decode(string(bpkey)); err == nil {
		t.Fatal("Expected error on decode with bad checksum")
	}

	if _, err := Decode(PrefixByteUser, pkey); err == nil {
		t.Fatal("Expected error on Decode with mismatched prefix")
	}
	if _, err := Decode(PrefixByte(3<<3), pkey); err == nil {
		t.Fatal("Expected error on Decode with invalid prefix")
	}
	if _, err := Decode(PrefixByteAccount, string(bpkey)); err == nil {
		t.Fatal("Expected error on Decode with bad checksum")
	}
	// Seed version
	if _, _, err := DecodeSeed(string(bpkey)); err == nil {
		t.Fatal("Expected error on DecodeSeed with bad checksum")
	}
	if _, _, err := DecodeSeed(pkey); err == nil {
		t.Fatal("Expected error on DecodeSeed with bad seed type")
	}

	seed, _ := account.Seed()
	bseed := []byte(seed)
	bseed[1] = 'S'
	if _, _, err := DecodeSeed(string(bseed)); err == nil {
		t.Fatal("Expected error on DecodeSeed with bad prefix type")
	}
	if _, err := FromSeed(string(bseed)); err == nil {
		t.Fatal("Expected error on FromSeed with bad prefix type")
	}

	if _, err := FromPublicKey(string(bpkey)); err == nil {
		t.Fatal("Expected error on FromPublicKey with bad checksum")
	}
	if _, err := FromPublicKey(seed); err == nil {
		t.Fatal("Expected error on FromPublicKey with bad checksum")
	}
}
