package test

import (
	"context"
	"sync/atomic"
	"testing"

	"github.com/openpcc/openpcc/anonpay"
	"github.com/openpcc/openpcc/anonpay/banking"
	"github.com/openpcc/openpcc/anonpay/banking/inmem"
	"github.com/openpcc/openpcc/anonpay/currency"
	"github.com/openpcc/openpcc/internal/test/anonpaytest"
)

type FailingBlindBank struct {
	InMemBank                     *inmem.Bank
	FailDepositAfter              int
	FailWithdrawBatchAfter        int
	FailWithrawFullUnblindedAfter int
	FailExchangeAfter             int
	FailBalanceAfter              int
	depositCount                  *atomic.Int64
	withdrawBatchCount            *atomic.Int64
	withdrawFullCount             *atomic.Int64
	exchangeCount                 *atomic.Int64
	balanceCount                  *atomic.Int64
}

// NewFailingBlindBank creates a new blind bank that tracks the nr of calls
// made to its methods. After a configurable threshold is reached the methods
// wil begin returning [assert.AnError].
//
// By default none of the operations will fail in this way.
func NewFailingBlindBank(t *testing.T) *FailingBlindBank {
	issuer := anonpaytest.MustNewIssuer()
	srcBank := inmem.NewBankWithRoundFunc(issuer, &anonpaytest.NoopNonceLocker{}, func(signedAmount float64) (currency.Value, error) {
		// always round down in test cases for consistent results.
		return currency.Rounded(signedAmount, 0)
	})
	return &FailingBlindBank{
		InMemBank:                     srcBank,
		FailDepositAfter:              -1,
		FailWithdrawBatchAfter:        -1,
		FailWithrawFullUnblindedAfter: -1,
		FailExchangeAfter:             -1,
		FailBalanceAfter:              -1,
		depositCount:                  &atomic.Int64{},
		withdrawBatchCount:            &atomic.Int64{},
		withdrawFullCount:             &atomic.Int64{},
		exchangeCount:                 &atomic.Int64{},
		balanceCount:                  &atomic.Int64{},
	}
}

func (b *FailingBlindBank) Deposit(ctx context.Context, transferID []byte, account banking.AccountToken, credit *anonpay.BlindedCredit) (int64, error) {
	if err := failingOpCall(b.FailDepositAfter, b.depositCount); err != nil {
		return 0, err
	}

	return b.InMemBank.Deposit(ctx, transferID, account, credit)
}

func (b *FailingBlindBank) WithdrawBatch(ctx context.Context, transferID []byte, account banking.AccountToken, reqs []anonpay.BlindSignRequest) (int64, [][]byte, error) {
	if err := failingOpCall(b.FailWithdrawBatchAfter, b.withdrawBatchCount); err != nil {
		return 0, nil, err
	}

	return b.InMemBank.WithdrawBatch(ctx, transferID, account, reqs)
}

func (b *FailingBlindBank) WithdrawFullUnblinded(ctx context.Context, transferID []byte, account banking.AccountToken) (*anonpay.UnblindedCredit, error) {
	if err := failingOpCall(b.FailWithrawFullUnblindedAfter, b.withdrawFullCount); err != nil {
		return nil, err
	}

	return b.InMemBank.WithdrawFullUnblinded(ctx, transferID, account)
}

func (b *FailingBlindBank) Exchange(ctx context.Context, transferID []byte, credit anonpay.AnyCredit, request anonpay.BlindSignRequest) ([]byte, error) {
	if err := failingOpCall(b.FailExchangeAfter, b.exchangeCount); err != nil {
		return nil, err
	}

	return b.InMemBank.Exchange(ctx, transferID, credit, request)
}

func (b *FailingBlindBank) Balance(ctx context.Context, account banking.AccountToken) (int64, error) {
	if err := failingOpCall(b.FailBalanceAfter, b.balanceCount); err != nil {
		return 0, err
	}

	return b.InMemBank.Balance(ctx, account)
}
