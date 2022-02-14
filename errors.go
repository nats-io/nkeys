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

// Errors
const (
	ErrInvalidPrefixByte = nkeysError("nkeys: invalid prefix byte")
	ErrInvalidKey        = nkeysError("nkeys: invalid key")
	ErrInvalidPublicKey  = nkeysError("nkeys: invalid public key")
	ErrInvalidSeedLen    = nkeysError("nkeys: invalid seed length")
	ErrInvalidSeed       = nkeysError("nkeys: invalid seed")
	ErrInvalidEncoding   = nkeysError("nkeys: invalid encoded key")
	ErrInvalidSignature  = nkeysError("nkeys: signature verification failed")
	ErrCannotSign        = nkeysError("nkeys: can not sign, no private key available")
	ErrPublicKeyOnly     = nkeysError("nkeys: no seed or private key available")
	ErrIncompatibleKey   = nkeysError("nkeys: incompatible key")
	ErrInvalidChecksum   = nkeysError("nkeys: invalid checksum")
	ErrNoSeedFound       = nkeysError("no nkey seed found")
	ErrInvalidNkeySeed   = nkeysError("doesn't contain a seed nkey")
	ErrInvalidUserSeed   = nkeysError("doesn't contain an user seed nkey")
)

type nkeysError string

func (e nkeysError) Error() string {
	return string(e)
}
