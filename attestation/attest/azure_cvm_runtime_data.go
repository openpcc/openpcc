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

package attest

import (
	"bytes"
	"context"
	"fmt"

	sabi "github.com/google/go-sev-guest/abi"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/google/go-tpm/tpmutil"
	"github.com/openpcc/openpcc/attestation/evidence"
	cstpm "github.com/openpcc/openpcc/tpm"
)

const (
	// Experimentally we see 20 bytes after the TEE report, some of which are non-zero,
	// their purpose does not seem to be documented publicly.
	AzureReportRuntimeDataBufferSize uint32 = 20
)

type AzureCVMRuntimeDataAttestor struct {
	tpm   transport.TPM
	Nonce []byte
}

func NewAzureCVMRuntimeDataAttestor(tpm transport.TPM, nonce []byte) *AzureCVMRuntimeDataAttestor {
	return &AzureCVMRuntimeDataAttestor{
		tpm:   tpm,
		Nonce: nonce,
	}
}

func (*AzureCVMRuntimeDataAttestor) Name() string {
	return "AzureCVMRuntimeDataAttestor"
}

func (a *AzureCVMRuntimeDataAttestor) CreateSignedEvidence(ctx context.Context) (*evidence.SignedEvidencePiece, error) {
	emptyNonce := make([]byte, sabi.ReportDataSize)

	err := cstpm.WriteToNVRamNoAuth(
		a.tpm,
		tpmutil.Handle(AzureTDReportWriteNVIndex),
		emptyNonce)

	if err != nil {
		return nil, fmt.Errorf(
			"failed to write empty nonce to NV index (%x): %w",
			AzureTDReportWriteNVIndex,
			err)
	}

	raw, err := cstpm.NVReadEXNoAuthorization(a.tpm, tpmutil.Handle(AzureTDReportReadNVIndex))
	if err != nil {
		return nil, fmt.Errorf("failed to read TD report from NV index (%x): %w", AzureTDReportReadNVIndex, err)
	}

	rawJsonBytes := raw[(AzureSEVSNPReportOffset + AzureSEVSNPReportSize + AzureReportRuntimeDataBufferSize):]
	// There is a seemingly arbitrary number of null bytes after the runtime data, these are not included in
	// the signature of the runtime data that ends up in the TEE report, so we drop them here.
	rawJsonBytesTrimmed := bytes.TrimRight(rawJsonBytes, "\x00")

	runtimeData := &evidence.AzureCVMRuntimeData{}

	err = runtimeData.UnmarshalJSON(rawJsonBytesTrimmed)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal runtime data: %w", err)
	}

	runtimeDataSerialized, err := runtimeData.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("failed to marshal runtime data to proto: %w", err)
	}

	return &evidence.SignedEvidencePiece{
		Data:      runtimeDataSerialized,
		Signature: runtimeData.Signature[:],
		Type:      evidence.AzureRuntimeData,
	}, nil
}
