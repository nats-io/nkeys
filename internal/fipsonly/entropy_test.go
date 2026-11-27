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

// Go 1.27 is the first release whose crypto/ed25519 refuses caller-supplied
// randomness in FIPS-only mode; earlier releases accept it.
//
//go:build go1.27

package fipsonly

import (
	"bytes"
	"testing"

	"github.com/nats-io/nkeys"
)

// TestCustomEntropyRefused checks that CreatePairWithRand keeps refusing
// caller-supplied entropy in FIPS-only mode, rather than turning it into a
// key pair presented as generated. This pins the behavior of the creation API
// only: importing a seed with FromRawSeed is allowed in every mode, and where
// an imported seed came from is outside what this library can check.
func TestCustomEntropyRefused(t *testing.T) {
	for _, prefix := range ed25519Prefixes {
		t.Run(prefix.String(), func(t *testing.T) {
			entropy := bytes.NewReader(make([]byte, 32))
			if _, err := nkeys.CreatePairWithRand(prefix, entropy); err == nil {
				t.Fatal("CreatePairWithRand accepted caller-supplied entropy in FIPS-only mode")
			}
		})
	}
}
