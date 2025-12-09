package httpapi_test

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/cenkalti/backoff/v4"
	"github.com/openpcc/openpcc/anonpay"
	"github.com/openpcc/openpcc/anonpay/banking"
	"github.com/openpcc/openpcc/anonpay/banking/httpapi"
	"github.com/openpcc/openpcc/anonpay/banking/inmem"
	"github.com/openpcc/openpcc/anonpay/banking/testcontract"
	"github.com/openpcc/openpcc/internal/test/anonpaytest"
)

func TestContract(t *testing.T) {
	httpClient := &http.Client{
		Timeout: 10 * time.Second,
	}

	testcontract.TestBlindBankContract(t, func(t *testing.T, nonceLocker anonpay.NonceLocker) (banking.BlindBankContract, error) {
		issuer := anonpaytest.MustNewIssuer()
		inmemBank := inmem.NewBank(issuer, nonceLocker)
		server := httpapi.NewServer(inmemBank)

		srv := httptest.NewServer(server)
		t.Cleanup(func() {
			srv.Close()
		})

		return httpapi.NewClientWithBackoff(httpClient, srv.URL, func() backoff.BackOff {
			return &backoff.StopBackOff{}
		})
	})
}
