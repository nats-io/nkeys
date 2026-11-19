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

package main

import "testing"

func TestGetVersionUsesLinkerVersion(t *testing.T) {
	orig := Version
	defer func() { Version = orig }()

	Version = "v9.9.9"
	if v := getVersion(); v != "v9.9.9" {
		t.Fatalf("expected linker version v9.9.9, got %q", v)
	}
}

func TestGetVersionFallbackIsNonEmpty(t *testing.T) {
	orig := Version
	defer func() { Version = orig }()

	// Simulates a `go install ...@version` build where ldflags did not set Version.
	Version = ""
	if v := getVersion(); v == "" {
		t.Fatal("expected a non-empty fallback version when Version is unset")
	}
}
