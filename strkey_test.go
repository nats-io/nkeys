// Copyright 2023 The NATS Authors
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
	"encoding/binary"
	"testing"
)

func TestRejectSmallOrderPublicKeys(t *testing.T) {
	// The eight canonical small-order point encodings, followed by all six
	// noncanonical encodings rejected by the blocklist.
	points := [...][32]byte{
		{1},
		{236, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 127},
		{},
		{31: 128},
		{38, 232, 149, 143, 194, 178, 39, 176, 69, 195, 244, 137, 242, 239, 152, 240, 213, 223, 172, 5, 211, 198, 51, 57, 177, 56, 2, 136, 109, 83, 252, 5},
		{38, 232, 149, 143, 194, 178, 39, 176, 69, 195, 244, 137, 242, 239, 152, 240, 213, 223, 172, 5, 211, 198, 51, 57, 177, 56, 2, 136, 109, 83, 252, 133},
		{199, 23, 106, 112, 61, 77, 216, 79, 186, 60, 11, 118, 13, 16, 103, 15, 42, 32, 83, 250, 44, 57, 204, 198, 78, 199, 253, 119, 146, 172, 3, 122},
		{199, 23, 106, 112, 61, 77, 216, 79, 186, 60, 11, 118, 13, 16, 103, 15, 42, 32, 83, 250, 44, 57, 204, 198, 78, 199, 253, 119, 146, 172, 3, 250},
		{0: 1, 31: 128},
		{236, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255},
		{237, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 127},
		{237, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255},
		{238, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 127},
		{238, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255},
	}

	validators := []struct {
		prefix PrefixByte
		valid  func(string) bool
	}{
		{PrefixByteOperator, IsValidPublicOperatorKey},
		{PrefixByteServer, IsValidPublicServerKey},
		{PrefixByteCluster, IsValidPublicClusterKey},
		{PrefixByteAccount, IsValidPublicAccountKey},
		{PrefixByteUser, IsValidPublicUserKey},
	}

	for encoding, point := range points {
		for _, validator := range validators {
			encoded, err := Encode(validator.prefix, point[:])
			if err != nil {
				t.Fatal(err)
			}
			public := string(encoded)

			if IsValidPublicKey(public) {
				t.Fatalf("small order encoding %d with prefix %s passed general validation", encoding, validator.prefix)
			}
			if validator.valid(public) {
				t.Fatalf("small order encoding %d with prefix %s passed typed validation", encoding, validator.prefix)
			}
			if _, err := FromPublicKey(public); err != ErrInvalidPublicKey {
				t.Fatalf("small order encoding %d with prefix %s: expected %v, got %v", encoding, validator.prefix, ErrInvalidPublicKey, err)
			}
		}
	}
}

func BenchmarkDecode(b *testing.B) {
	tcs := []struct {
		name string
		f    func([]byte) ([]byte, error)
	}{
		{"original", func(src []byte) ([]byte, error) {
			raw := make([]byte, b32Enc.DecodedLen(len(src)))
			n, err := b32Enc.Decode(raw, src)
			if err != nil {
				return nil, err
			}
			raw = raw[:n]

			if len(raw) < 4 {
				return nil, ErrInvalidEncoding
			}

			var crc uint16
			checksum := bytes.NewReader(raw[len(raw)-2:])
			if err := binary.Read(checksum, binary.LittleEndian, &crc); err != nil {
				return nil, err
			}

			// ensure checksum is valid
			if err := validate(raw[0:len(raw)-2], crc); err != nil {
				return nil, err
			}
			return raw[:len(raw)-2], nil
		}},
		{"current", decode},
	}
	for _, tc := range tcs {
		b.Run(tc.name, func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				if _, err := tc.f([]byte("SUAMAR5BIQ2AZCPYRTLLK7UGWMGSG2GWD2VPIXBNO7ZIB6TZAU4QAEJS2Q")); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
