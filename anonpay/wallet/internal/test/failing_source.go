package test

import (
	"context"
	"sync/atomic"
	"testing"

	"github.com/openpcc/openpcc/anonpay"
	"github.com/openpcc/openpcc/anonpay/currency"
	"github.com/stretchr/testify/assert"
)

type FailingSource struct {
	WorkingSource     *Source
	FailDepositAfter  int
	FailWithdrawAfter int
	depositCount      *atomic.Int64
	withdrawCount     *atomic.Int64
}

// NewFailingSource creates a new source that tracks the nr of calls
// made to its methods. After a configurable threshold is reached the methods
// wil begin returning [assert.AnError].
//
// By default none of the operations will fail in this way.
func NewFailingSource(t *testing.T, balance int64) *FailingSource {
	return &FailingSource{
		WorkingSource:     NewSource(t, balance),
		FailDepositAfter:  -1,
		FailWithdrawAfter: -1,
		depositCount:      &atomic.Int64{},
		withdrawCount:     &atomic.Int64{},
	}
}

func (s *FailingSource) Deposit(ctx context.Context, transferID []byte, credits ...*anonpay.BlindedCredit) error {
	if err := failingOpCall(s.FailDepositAfter, s.depositCount); err != nil {
		return err
	}

	return s.WorkingSource.Deposit(ctx, transferID, credits...)
}

func (s *FailingSource) Withdraw(ctx context.Context, transferID []byte, amount currency.Value) (*anonpay.BlindedCredit, error) {
	if err := failingOpCall(s.FailWithdrawAfter, s.withdrawCount); err != nil {
		return nil, err
	}

	return s.WorkingSource.Withdraw(ctx, transferID, amount)
}

func failingOpCall(threshold int, counter *atomic.Int64) error {
	op := counter.Add(1)
	if threshold >= 0 && op > int64(threshold) {
		return assert.AnError
	}

	return nil
}
