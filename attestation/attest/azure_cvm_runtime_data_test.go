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
package attest_test

import (
	_ "embed"
	"encoding/pem"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/google/go-tpm/tpm2/transport/simulator"
	"github.com/openpcc/openpcc/attestation/attest"
	"github.com/openpcc/openpcc/attestation/evidence"
	"github.com/openpcc/openpcc/attestation/verify"
	test "github.com/openpcc/openpcc/inttest"
)

func Test_AzureCVMRuntimeData_Success(t *testing.T) {
	reportFS := test.TextArchiveFS(t, "testdata/azure_sevsnp_report.txt")
	testAzureSEVSNPReportPEM := test.ReadFile(t, reportFS, "test_azure_sevsnp_report.pem")

	thetpm, err := simulator.OpenSimulator()
	if err != nil {
		t.Fatalf("could not connect to TPM simulator: %v", err)
	}

	t.Cleanup(func() {
		if err := thetpm.Close(); err != nil {
			t.Errorf("%v", err)
		}
	})

	block, _ := pem.Decode(testAzureSEVSNPReportPEM)
	require.NotNil(t, block)

	mocktpm := &TPMNVWrapper{
		realtpm:       thetpm,
		responseBytes: block.Bytes,
	}

	attestor := attest.NewAzureCVMRuntimeDataAttestor(
		mocktpm,
		make([]byte, 64),
	)
	se, err := attestor.CreateSignedEvidence(t.Context())

	require.NoError(t, err)
	require.NotNil(t, se)

	err = verify.AzureCVMRuntimeData(t.Context(), se)

	require.NoError(t, err)
}

func Test_AzureCVMRuntimeData_FailureSignatureMismatch(t *testing.T) {
	reportFS := test.TextArchiveFS(t, "testdata/azure_sevsnp_report.txt")
	testAzureSEVSNPReportPEM := test.ReadFile(t, reportFS, "test_azure_sevsnp_report.pem")

	thetpm, err := simulator.OpenSimulator()
	if err != nil {
		t.Fatalf("could not connect to TPM simulator: %v", err)
	}

	t.Cleanup(func() {
		if err := thetpm.Close(); err != nil {
			t.Errorf("%v", err)
		}
	})

	block, _ := pem.Decode(testAzureSEVSNPReportPEM)
	require.NotNil(t, block)

	mocktpm := &TPMNVWrapper{
		realtpm:       thetpm,
		responseBytes: block.Bytes,
	}

	attestor := attest.NewAzureCVMRuntimeDataAttestor(
		mocktpm,
		make([]byte, 64),
	)
	se, err := attestor.CreateSignedEvidence(t.Context())

	require.NoError(t, err)
	require.NotNil(t, se)

	runtimeData := &evidence.AzureCVMRuntimeData{}
	runtimeData.UnmarshalBinary(se.Data)

	// Modify the proto in some way
	runtimeData.AzureCVMConfiguration.TpmEnabled = false

	newBytes, err := runtimeData.MarshalBinary()
	require.NoError(t, err)
	require.NotNil(t, newBytes)

	se.Data = newBytes

	err = verify.AzureCVMRuntimeData(t.Context(), se)

	require.ErrorContains(t, err, "struct does not match its original json")
}
