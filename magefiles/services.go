// Copyright 2025 Nonvolatile Inc. d/b/a Confident Security

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at

//     https://www.apache.org/licenses/LICENSE-2.0

// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"github.com/magefile/mage/sh"
)

func RunAuth() {
	sh.RunV("go", "run", "./cmd/mem-auth")
}

func RunBank() {
	sh.RunV("go", "run", "./cmd/mem-bank")
}

func RunOhttpRelay() {
	sh.RunV("go", "run", "./cmd/ohttp-relay")
}

func RunGateway() {
	sh.RunV("go", "run", "./cmd/mem-gateway")
}

func RunCredithole() {
	sh.RunV("go", "run", "./cmd/mem-credithole")
}

func RunRouter() {
	sh.RunV("go", "run", "./cmd/mem-router")
}

func RunCompute() {
	sh.RunV("go", "run", "-tags=include_fake_attestation", "./cmd/mem-compute")
}

func RunClient() {
	sh.RunV("go", "run", "-tags=include_fake_attestation", "./cmd/test-client")
}

func RunMemServices() {
	sh.RunV("go", "tool", "reflex", "-d", "fancy", "-c", "reflex.conf")
}
