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
	"context"
	"errors"
	"fmt"
	"log/slog"

	"github.com/openpcc/openpcc/attestation/evidence"

	"github.com/confidentsecurity/go-nvtrust/pkg/gonvtrust"
)

type AttestationProvider interface {
	Attest(ctx context.Context, nonce []byte) (*gonvtrust.AttestationResult, error)
}

type NVidiaAttestor struct {
	Nonce             []byte
	Provider          AttestationProvider
	EvidenceType      evidence.EvidenceType
	AttestationResult *gonvtrust.AttestationResult
}

func NewNVidiaAttestor(provider AttestationProvider, evidenceType evidence.EvidenceType, nonce []byte) (*NVidiaAttestor, error) {
	return &NVidiaAttestor{
		Nonce:        nonce,
		Provider:     provider,
		EvidenceType: evidenceType,
	}, nil
}

func (*NVidiaAttestor) Name() string {
	return "NvidiaCCAttestor"
}

func (a *NVidiaAttestor) CreateSignedEvidence(ctx context.Context) (*evidence.SignedEvidencePiece, error) {
	if len(a.Nonce) != 32 {
		return nil, fmt.Errorf("the TEENonce size is %d. TDX device requires 32 bytes", len(a.Nonce))
	}

	var err error
	a.AttestationResult, err = a.Provider.Attest(ctx, a.Nonce)
	slog.Info("attestation result", "result", a.AttestationResult)
	if err != nil {
		return nil, fmt.Errorf("failed to get remote evidence: %w", err)
	}

	if !a.AttestationResult.Result {
		return nil, errors.New("attestation failed")
	}

	slog.Info("attestation successful", "jwtToken", a.AttestationResult.JWTToken.Raw, "gpuToken", a.AttestationResult.DevicesTokens["GPU-0"])

	evidencePiece, err := evidence.SignedEvidencePieceFromJWT(a.AttestationResult.JWTToken, a.EvidenceType)
	if err != nil {
		return nil, fmt.Errorf("failed to create evidence piece: %w", err)
	}

	return evidencePiece, nil
}
