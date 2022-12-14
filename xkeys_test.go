// Copyright 2022 The NATS Authors
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
	"reflect"
	"testing"
)

func testCurve(t *testing.T, kp KeyPair) {
	// Check seed
	seed, err := kp.Seed()
	if err != nil {
		t.Fatalf("Unexpected error retrieving seed: %v", err)
	}
	_, err = Decode(PrefixByteSeed, seed)
	if err != nil {
		t.Fatalf("Expected a proper seed string, got %s with err: %v", seed, err)
	}
	if pb, _, err := DecodeSeed(seed); err != nil || pb != PrefixByteCurve {
		t.Fatalf("Expected a proper seed string, got %s", seed)
	}

	// Check public key
	pub, err := kp.PublicKey()
	if err != nil {
		t.Fatalf("Received an error retrieving public key: %v", err)
	}
	if pub[0] != 'X' {
		t.Fatalf("Expected a prefix of 'X' but got %c", pub[0])
	}
	if !IsValidPublicCurveKey(pub) {
		t.Fatalf("Not a valid public curve key")
	}

	// Check private key
	private, err := kp.PrivateKey()
	if err != nil {
		t.Fatalf("Received an error retrieving private key: %v", err)
	}
	if private[0] != 'P' {
		t.Fatalf("Expected a prefix of 'P' but got %v", private[0])
	}

	// Seal
	rkp, _ := CreateCurveKeys()
	rpub, _ := rkp.PublicKey()

	msg := []byte("Hello xkeys!")
	encrypted, err := kp.Seal(msg, rpub)
	if err != nil {
		t.Fatalf("Received an error on Seal: %v", err)
	}

	decrypted, err := rkp.Open(encrypted, pub)
	if err != nil {
		t.Fatalf("Received an error on Open: %v", err)
	}
	if !bytes.Equal(decrypted, msg) {
		t.Fatalf("Expected %q to be %q", decrypted, msg)
	}
}

func TestCurveFromCreateCurveKeys(t *testing.T) {
	kp, err := CreateCurveKeys()
	if err != nil {
		t.Fatalf("Expected nil error on CreateCurveKeys, received %v", err)
	}
	if kp == nil {
		t.Fatal("Expected a non-nil curve key pair")
	}
	testCurve(t, kp)
}

func TestCurveFromCreatePair(t *testing.T) {
	kp, err := CreatePair(PrefixByteCurve)
	if err != nil {
		t.Fatalf("Expected nil error on CreatePair, received %v", err)
	}
	if kp == nil {
		t.Fatal("Expected a non-nil curve key pair")
	}
	testCurve(t, kp)
}

func TestCurveFromSeed(t *testing.T) {
	kp, _ := CreateCurveKeys()
	seed, _ := kp.Seed()

	nkp, err := FromCurveSeed(seed)
	if err != nil {
		t.Fatalf("Unexpected error deriving curve keypair: %v", err)
	}
	if !reflect.DeepEqual(kp.(*ckp), nkp.(*ckp)) {
		t.Fatal("Expected the curve pairs to be equal")
	}
	testCurve(t, nkp)
}

func TestCurveFromKeyPair(t *testing.T) {
	kp, _ := CreatePair(PrefixByteCurve)
	_, err := kp.Sign([]byte("hello"))
	if err == nil {
		t.Fatal("Expected sign to fail as it non supported operation")
	}
	if err != ErrInvalidCurveKeyOperation {
		t.Fatalf("Expected %v but got %v", ErrInvalidCurveKeyOperation, err)
	}
	err = kp.Verify([]byte("hello"), []byte("bad"))
	if err == nil {
		t.Fatal("Expected verify to fail as it is unsupported operation")
	}
	if err != ErrInvalidCurveKeyOperation {
		t.Fatalf("Expected %v but got %v", ErrInvalidCurveKeyOperation, err)
	}
}

func TestCurvePublic(t *testing.T) {
	kp, _ := CreatePair(PrefixByteCurve)
	_, err := kp.Sign([]byte("hello"))
	if err == nil {
		t.Fatal("Expected sign to fail as it non supported operation")
	}
	pk, err := kp.PublicKey()
	if err != nil {
		t.Fatalf("Unexpected public key error: %v", err)
	}
	pub, err := FromPublicKey(pk)
	if err != nil {
		t.Fatalf("Unexpected error when creating public key: %v", err)
	}
	_, err = pub.Open([]byte("hello"), "bad")
	if err != ErrCannotOpen {
		t.Fatalf("Expected %v but got %v", ErrCannotOpen, err)
	}
	_, err = pub.Seal([]byte("hello"), "bad")
	if err != ErrCannotSeal {
		t.Fatalf("Expected %v but got %v", ErrCannotSeal, err)
	}
	_, err = pub.SealWithRand([]byte("hello"), "bad", nil)
	if err != ErrCannotSeal {
		t.Fatalf("Expected %v but got %v", ErrCannotSeal, err)
	}
}
