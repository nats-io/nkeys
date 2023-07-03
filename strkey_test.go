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
