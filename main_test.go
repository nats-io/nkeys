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
	"encoding/base64"
	"io"
	"regexp"
	"testing"

	"golang.org/x/crypto/ed25519"
)

func TestVersion(t *testing.T) {
	// Semantic versioning
	verRe := regexp.MustCompile(`\d+.\d+.\d+(-\S+)?`)
	if !verRe.MatchString(Version) {
		t.Fatalf("Version not compatible with semantic versioning: %q", Version)
	}
}

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
	if str != nil {
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
	var rawKeyShort [16]byte

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

	var rawSeed [ed25519.SeedSize]byte

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
	account, err := CreateAccount()
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
	user, err := CreateUser()
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

func TestOperator(t *testing.T) {
	operator, err := CreateOperator()
	if err != nil {
		t.Fatalf("Expected non-nil error on CreateOperator, received %v", err)
	}
	if operator == nil {
		t.Fatal("Expect a non-nil operator")
	}

	// Check Public
	public, err := operator.PublicKey()
	if err != nil {
		t.Fatalf("Received an error retrieving public key: %v", err)
	}
	if public[0] != 'O' {
		t.Fatalf("Expected a prefix of 'O' but got %c", public[0])
	}
	if !IsValidPublicOperatorKey(public) {
		t.Fatalf("Not a valid public cluster key")
	}
}

func TestCluster(t *testing.T) {
	cluster, err := CreateCluster()
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
	server, err := CreateServer()
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

func TestPrefixByte(t *testing.T) {
	user, _ := CreateUser()
	pub, _ := user.PublicKey()
	if pre := Prefix(pub); pre != PrefixByteUser {
		t.Fatalf("Expected %s, got %s\n", PrefixByteUser, pre)
	}
	seed, _ := user.Seed()
	if pre := Prefix(string(seed)); pre != PrefixByteSeed {
		t.Fatalf("Expected %s, got %s\n", PrefixByteSeed, pre)
	}
	if pre := Prefix("SEED"); pre != PrefixByteUknown {
		t.Fatalf("Expected %s, got %s\n", PrefixByteUknown, pre)
	}
	account, _ := CreateAccount()
	pub, _ = account.PublicKey()
	if pre := Prefix(pub); pre != PrefixByteAccount {
		t.Fatalf("Expected %s, got %s\n", PrefixByteAccount, pre)
	}
}

func TestIsValidPublic(t *testing.T) {
	user, _ := CreateUser()
	pub, _ := user.PublicKey()
	if !IsValidPublicKey(pub) {
		t.Fatalf("Expected pub to be a valid public key")
	}
	seed, _ := user.Seed()
	if IsValidPublicKey(string(seed)) {
		t.Fatalf("Expected seed to not be a valid public key")
	}
	if IsValidPublicKey("BAD") {
		t.Fatalf("Expected BAD to not be a valid public key")
	}
	account, _ := CreateAccount()
	pub, _ = account.PublicKey()
	if !IsValidPublicKey(pub) {
		t.Fatalf("Expected pub to be a valid public key")
	}
}

func TestFromPublic(t *testing.T) {
	// Create a User
	user, err := CreateUser()
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
	publicKeyClone, _ := user.PublicKey()
	if publicKeyClone != publicKey {
		t.Fatalf("Expected the public keys to match: %q vs %q", publicKeyClone, publicKey)
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
	if publicKey2 != publicKey {
		t.Fatalf("Expected the public keys to match: %q vs %q", publicKey2, publicKey)
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
	user2, _ := CreateUser()
	sig, _ = user2.Sign(data)

	err = pubUser.Verify(data, sig)
	if err == nil {
		t.Fatalf("Expected verification to fail.")
	}
}

func TestFromSeed(t *testing.T) {
	account, err := CreateAccount()
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
	if !bytes.HasPrefix(seed, []byte("SA")) {
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
	if _, err := EncodeSeed(PrefixByteUser, tooshort[:]); err == nil {
		t.Fatal("Expected an error with insufficient rand")
	}

	if _, err := CreatePair(PrefixBytePrivate); err == nil {
		t.Fatal("Expected an error with non-public prefix")
	}
	kpbad := &kp{[]byte("SEEDBAD")}
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
	if _, err := decode([]byte("foo!")); err == nil {
		t.Fatal("Expected an error decoding non-base32")
	}
	if _, err := decode([]byte("OK")); err == nil {
		t.Fatal("Expected an error decoding a too short string")
	}

	// Create invalid checksum
	account, _ := CreateAccount()
	pkey, _ := account.PublicKey()
	bpkey := []byte(pkey)
	bpkey[len(pkey)-1] = '0'
	bpkey[len(pkey)-2] = '0'
	if _, err := decode(bpkey); err == nil {
		t.Fatal("Expected error on decode with bad checksum")
	}

	if _, err := Decode(PrefixByteUser, []byte(pkey)); err == nil {
		t.Fatal("Expected error on Decode with mismatched prefix")
	}
	if _, err := Decode(PrefixByte(3<<3), []byte(pkey)); err == nil {
		t.Fatal("Expected error on Decode with invalid prefix")
	}
	if _, err := Decode(PrefixByteAccount, bpkey); err == nil {
		t.Fatal("Expected error on Decode with bad checksum")
	}
	// Seed version
	if _, _, err := DecodeSeed(bpkey); err == nil {
		t.Fatal("Expected error on DecodeSeed with bad checksum")
	}
	if _, _, err := DecodeSeed([]byte(pkey)); err == nil {
		t.Fatal("Expected error on DecodeSeed with bad seed type")
	}

	seed, _ := account.Seed()
	bseed := []byte(seed)
	bseed[1] = 'S'
	if _, _, err := DecodeSeed(bseed); err == nil {
		t.Fatal("Expected error on DecodeSeed with bad prefix type")
	}
	if _, err := FromSeed(bseed); err == nil {
		t.Fatal("Expected error on FromSeed with bad prefix type")
	}

	if _, err := FromPublicKey(string(bpkey)); err == nil {
		t.Fatal("Expected error on FromPublicKey with bad checksum")
	}
	if _, err := FromPublicKey(string(seed)); err == nil {
		t.Fatal("Expected error on FromPublicKey with bad checksum")
	}
}

func TestFromRawSeed(t *testing.T) {
	user, err := CreateUser()
	if err != nil {
		t.Fatalf("Expected non-nil error on CreateUser, received %v", err)
	}
	se, _ := user.Seed()
	_, raw, _ := DecodeSeed(se)
	user2, err := FromRawSeed(PrefixByteUser, raw)
	if err != nil {
		t.Fatalf("Expected non-nil error on FromRawSeed, received %v", err)
	}
	s2e, _ := user2.Seed()
	if !bytes.Equal(se, s2e) {
		t.Fatalf("Expected the seeds to be the same, got %v vs %v\n", se, s2e)
	}
}

func TestWipe(t *testing.T) {
	user, err := CreateUser()
	if err != nil {
		t.Fatalf("Expected non-nil error on CreateUser, received %v", err)
	}
	pubKey, err := user.PublicKey()
	if err != nil {
		t.Fatalf("Received an error retrieving public key: %v", err)
	}
	seed := user.(*kp).seed
	// Copy so we know the original
	copy := append([]byte{}, seed...)
	user.Wipe()
	// Make sure new seed is nil
	if wiped := user.(*kp).seed; wiped != nil {
		t.Fatalf("Expected the seed to be nil, got %q", wiped)
	}
	// Make sure the original seed is not equal to the seed in memory.
	if bytes.Equal(seed, copy) {
		t.Fatalf("Expected the memory for the seed to be randomized")
	}

	// Now test public
	user, err = FromPublicKey(pubKey)
	if err != nil {
		t.Fatalf("Received an error create KeyPair from PublicKey: %v", err)
	}

	edPub := user.(*pub).pub
	// Copy so we know the original
	copy = append([]byte{}, edPub...)

	user.Wipe()

	// First check pre was changed
	if user.(*pub).pre != '0' {
		t.Fatalf("Expected prefix to be changed")
	}

	// Make sure the original key is not equal to the one in memory.
	if bytes.Equal(edPub, copy) {
		t.Fatalf("Expected the memory for the pubKey to be randomized")
	}
}

const (
	nonceRawLen = 16
	nonceLen    = 22 // base64.RawURLEncoding.EncodedLen(nonceRawLen)
)

func BenchmarkSign(b *testing.B) {
	data := make([]byte, nonceRawLen)
	nonce := make([]byte, nonceLen)
	rand.Read(data)
	base64.RawURLEncoding.Encode(nonce, data)

	user, err := CreateUser()
	if err != nil {
		b.Fatalf("Error creating User Nkey: %v", err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := user.Sign(nonce); err != nil {
			b.Fatalf("Error signing nonce: %v", err)
		}
	}
}

func BenchmarkVerify(b *testing.B) {
	data := make([]byte, nonceRawLen)
	nonce := make([]byte, nonceLen)
	rand.Read(data)
	base64.RawURLEncoding.Encode(nonce, data)

	user, err := CreateUser()
	if err != nil {
		b.Fatalf("Error creating User Nkey: %v", err)
	}
	sig, err := user.Sign(nonce)
	if err != nil {
		b.Fatalf("Error sigining nonce: %v", err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := user.Verify(nonce, sig); err != nil {
			b.Fatalf("Error verifying nonce: %v", err)
		}
	}
}

func BenchmarkPublicVerify(b *testing.B) {
	data := make([]byte, nonceRawLen)
	nonce := make([]byte, nonceLen)
	rand.Read(data)
	base64.RawURLEncoding.Encode(nonce, data)

	user, err := CreateUser()
	if err != nil {
		b.Fatalf("Error creating User Nkey: %v", err)
	}
	sig, err := user.Sign(nonce)
	if err != nil {
		b.Fatalf("Error sigining nonce: %v", err)
	}
	pk, err := user.PublicKey()
	if err != nil {
		b.Fatalf("Could not extract public key from user: %v", err)
	}
	pub, err := FromPublicKey(pk)
	if err != nil {
		b.Fatalf("Could not create public key pair from public key string: %v", err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := pub.Verify(nonce, sig); err != nil {
			b.Fatalf("Error verifying nonce: %v", err)
		}
	}
}
