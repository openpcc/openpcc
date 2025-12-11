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

package verify_test

import (
	"crypto/x509"
	"encoding/pem"
	"testing"

	"github.com/openpcc/openpcc/attestation/evidence"
	"github.com/openpcc/openpcc/attestation/verify"
	test "github.com/openpcc/openpcc/inttest"
	"github.com/stretchr/testify/require"
)

func TestGetIntermediateCert(t *testing.T) {
	testFS := test.TextArchiveFS(t, "./testdata/nvidia_certificates.txt")
	testIntermediateAKCert := test.ReadFile(t, testFS, "test_nvidia_cert.pem")
	t.Run("success", func(t *testing.T) {
		block, _ := pem.Decode(testIntermediateAKCert)
		require.NotNilf(t, block, "could not decode test certificate: PEM block is nil")

		intermediateCert, err := x509.ParseCertificate(block.Bytes)

		require.NoErrorf(t, err, "could not parse test certificate: %v", err)

		se := &evidence.SignedEvidencePiece{
			Type:      evidence.NvidiaCCIntermediateCertificate,
			Data:      intermediateCert.Raw,
			Signature: intermediateCert.Signature,
		}

		cert, err := verify.GetIntermediateCert(se)

		require.NoError(t, err)
		require.NotNil(t, cert)
	})
}
