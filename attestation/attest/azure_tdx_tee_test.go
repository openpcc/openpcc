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
	"context"
	_ "embed"
	"encoding/pem"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/openpcc/openpcc/attestation/attest"
	"github.com/openpcc/openpcc/attestation/evidence"
	"github.com/openpcc/openpcc/attestation/verify"

	"github.com/google/go-tdx-guest/abi"
	pb "github.com/google/go-tdx-guest/proto/tdx"
	"github.com/google/go-tdx-guest/verify/trust"
	"github.com/google/go-tpm/tpm2/transport/simulator"
	test "github.com/openpcc/openpcc/inttest"
)

type FakeMetadataQuoteService struct {
	Quote []byte
}

// Get uses http.Get to return the HTTPS response body as a byte array.
func (n *FakeMetadataQuoteService) GetQuote(_ context.Context, evidence []byte) ([]byte, error) {
	return n.Quote, nil
}
func Test_AzureTDXAttestor_Success(t *testing.T) {
	reportFS := test.TextArchiveFS(t, "testdata/azure_tdx_report.txt")
	testAzureTDXReportPEM := test.ReadFile(t, reportFS, "test_azure_tdx_report.pem")
	testAzureTDXQuotePEM := test.ReadFile(t, reportFS, "test_azure_tdx_quote.pem")

	tdxReportBytes, _ := pem.Decode(testAzureTDXReportPEM)
	require.NotNil(t, tdxReportBytes)

	tdxQuoteBytes, _ := pem.Decode(testAzureTDXQuotePEM)
	require.NotNil(t, tdxQuoteBytes)

	thetpm, err := simulator.OpenSimulator()
	if err != nil {
		t.Fatalf("could not connect to TPM simulator: %v", err)
	}

	t.Cleanup(func() {
		if err := thetpm.Close(); err != nil {
			t.Errorf("%v", err)
		}
	})
	mocktpm := &TPMNVWrapper{
		realtpm:       thetpm,
		responseBytes: tdxReportBytes.Bytes,
	}

	attestor := attest.NewAzureTDXTEEAttestorWithQuoteService(
		mocktpm,
		make([]byte, 64),
		&FakeMetadataQuoteService{
			Quote: tdxQuoteBytes.Bytes,
		},
	)
	se, err := attestor.CreateSignedEvidence(t.Context())

	require.NoError(t, err)
	require.NotNil(t, se)

	root, err := verify.GetTDXRootCert()

	require.NoError(t, err)

	quote, err := abi.QuoteToProto(tdxQuoteBytes.Bytes)

	require.NoError(t, err)

	quoteV4, ok := quote.(*pb.QuoteV4)

	require.True(t, ok)

	chain, err := attest.ExtractChainFromQuoteV4(quoteV4)
	require.NoError(t, err)

	collateralAttestor, err := attest.NewTDXCollateralAttestor(
		&trust.SimpleHTTPSGetter{},
		chain.PCKCertificate,
	)
	require.NoError(t, err)

	collateralEvidencePiece, err := collateralAttestor.CreateSignedEvidence(t.Context())

	require.NoError(t, err)

	tdxCollateral := &evidence.TDXCollateral{}

	tdxCollateral.UnmarshalBinary(collateralEvidencePiece.Data)

	err = verify.TDXReport(t.Context(), root, *tdxCollateral, se)

	// TODO(CS-1234): Re-enable this test
	// require.NoError(t, err)
}
