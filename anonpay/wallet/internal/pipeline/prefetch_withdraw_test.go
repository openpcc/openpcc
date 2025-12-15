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

package pipeline_test

import (
	"context"
	"slices"
	"testing"
	"time"

	"github.com/openpcc/openpcc/anonpay/currency"
	"github.com/openpcc/openpcc/anonpay/wallet/internal/pipeline"
	"github.com/openpcc/openpcc/anonpay/wallet/internal/stats"
	wtest "github.com/openpcc/openpcc/anonpay/wallet/internal/test"
	"github.com/openpcc/openpcc/anonpay/wallet/internal/transfer"
	test "github.com/openpcc/openpcc/inttest"
	"github.com/openpcc/openpcc/work"
	"github.com/stretchr/testify/require"
)

func TestPrefetchWithdrawSteps(t *testing.T) {
	tests := map[string]struct {
		maxExpiryDuration         time.Duration
		prefetchAmount            int64
		accounts                  []int64
		paymentReqs               []int64
		wantBatchesToConsolidate  []batch
		wantAccountsToConsolidate []int64
		wantPaymentReqs           []int64
		wantSplitAccountStats     stats.TransferCount
		wantPaymentRequestStats   stats.TransferCount
	}{
		"ok, no input": {
			prefetchAmount:            10,
			accounts:                  []int64{},
			paymentReqs:               []int64{},
			wantBatchesToConsolidate:  []batch{},
			wantAccountsToConsolidate: []int64{},
			wantPaymentReqs:           []int64{},
			wantSplitAccountStats:     stats.TransferCount{},
			wantPaymentRequestStats:   stats.TransferCount{},
		},
		"ok, no reqs, min account": {
			prefetchAmount:            1,
			accounts:                  []int64{1},
			paymentReqs:               []int64{},
			wantBatchesToConsolidate:  []batch{{1}},
			wantAccountsToConsolidate: []int64{},
			wantPaymentReqs:           []int64{},
			wantSplitAccountStats:     stats.TransferCount{Count: 1, Amount: 1, Credits: 1},
			wantPaymentRequestStats:   stats.TransferCount{},
		},
		"ok, no reqs, evenly split accounts": {
			prefetchAmount:            10,
			accounts:                  []int64{30, 20, 10},
			paymentReqs:               []int64{},
			wantBatchesToConsolidate:  []batch{{10, 10, 10}, {10, 10}, {10}},
			wantAccountsToConsolidate: []int64{},
			wantPaymentReqs:           []int64{},
			wantSplitAccountStats:     stats.TransferCount{Count: 3, Amount: 30 + 20 + 10, Credits: 3 + 2 + 1},
			wantPaymentRequestStats:   stats.TransferCount{},
		},
		"ok, no reqs, account under prefetch amount": {
			prefetchAmount:            10,
			accounts:                  []int64{9},
			wantBatchesToConsolidate:  []batch{},
			wantAccountsToConsolidate: []int64{9},
			wantSplitAccountStats:     stats.TransferCount{},
			wantPaymentRequestStats:   stats.TransferCount{},
		},
		"ok, no reqs, accounts have balance remaining after split": {
			prefetchAmount:            10,
			accounts:                  []int64{11, 22, 15},
			paymentReqs:               []int64{},
			wantBatchesToConsolidate:  []batch{{10}, {10, 10}, {10}},
			wantAccountsToConsolidate: []int64{1, 2, 5},
			wantPaymentReqs:           []int64{},
			wantSplitAccountStats:     stats.TransferCount{Count: 3, Amount: 10 + 20 + 10, Credits: 1 + 2 + 1},
			wantPaymentRequestStats:   stats.TransferCount{},
		},
		"ok, min req": {
			prefetchAmount:            1,
			accounts:                  []int64{1},
			paymentReqs:               []int64{1},
			wantBatchesToConsolidate:  []batch{},
			wantAccountsToConsolidate: []int64{},
			wantPaymentReqs:           []int64{1},
			wantSplitAccountStats:     stats.TransferCount{Count: 1, Amount: 1, Credits: 1},
			wantPaymentRequestStats:   stats.TransferCount{Count: 1, Amount: 1, Credits: 1},
		},
		"ok, min req, credit remaining in batch": {
			prefetchAmount:            1,
			accounts:                  []int64{2},
			paymentReqs:               []int64{1},
			wantBatchesToConsolidate:  []batch{{1}},
			wantAccountsToConsolidate: []int64{},
			wantPaymentReqs:           []int64{1},
			wantSplitAccountStats:     stats.TransferCount{Count: 1, Amount: 2, Credits: 2},
			wantPaymentRequestStats:   stats.TransferCount{Count: 1, Amount: 1, Credits: 1},
		},
		"ok, 100 reqs, 100 1-credit batches": {
			prefetchAmount:            5,
			accounts:                  slices.Repeat([]int64{5}, 100),
			paymentReqs:               slices.Repeat([]int64{5}, 100),
			wantBatchesToConsolidate:  []batch{},
			wantAccountsToConsolidate: []int64{},
			wantPaymentReqs:           slices.Repeat([]int64{5}, 100),
			wantSplitAccountStats:     stats.TransferCount{Count: 100, Amount: 5 * 100, Credits: 100},
			wantPaymentRequestStats:   stats.TransferCount{Count: 100, Amount: 5 * 100, Credits: 100},
		},
		"ok, 100 reqs, 50 2-credit batches": {
			prefetchAmount:            5,
			accounts:                  slices.Repeat([]int64{10}, 50),
			paymentReqs:               slices.Repeat([]int64{5}, 100),
			wantBatchesToConsolidate:  []batch{},
			wantAccountsToConsolidate: []int64{},
			wantPaymentReqs:           slices.Repeat([]int64{5}, 100),
			wantSplitAccountStats:     stats.TransferCount{Count: 50, Amount: 10 * 50, Credits: 100},
			wantPaymentRequestStats:   stats.TransferCount{Count: 100, Amount: 10 * 50, Credits: 100},
		},
		"ok, 100 reqs, 10 10-credit batches": {
			prefetchAmount:            5,
			accounts:                  slices.Repeat([]int64{50}, 10),
			paymentReqs:               slices.Repeat([]int64{5}, 100),
			wantBatchesToConsolidate:  []batch{},
			wantAccountsToConsolidate: []int64{},
			wantPaymentReqs:           slices.Repeat([]int64{5}, 100),
			wantSplitAccountStats:     stats.TransferCount{Count: 10, Amount: 10 * 50, Credits: 100},
			wantPaymentRequestStats:   stats.TransferCount{Count: 100, Amount: 5 * 100, Credits: 100},
		},
		"ok, 3 reqs, 2-credit batches, partial remaining batch": {
			prefetchAmount:            5,
			accounts:                  []int64{10, 10},
			paymentReqs:               []int64{5, 5, 5},
			wantBatchesToConsolidate:  []batch{{5}},
			wantAccountsToConsolidate: []int64{},
			wantPaymentReqs:           []int64{5, 5, 5},
			wantSplitAccountStats:     stats.TransferCount{Count: 2, Amount: 10 + 10, Credits: 4},
			wantPaymentRequestStats:   stats.TransferCount{Count: 3, Amount: 5 + 5 + 5, Credits: 3},
		},
		"ok, 4 reqs, mixed-credit batches, partial remaining batch": {
			prefetchAmount:            5,
			accounts:                  []int64{5, 10, 10, 15},
			paymentReqs:               []int64{5, 5, 5, 5},
			wantBatchesToConsolidate:  []batch{{5}, {5, 5, 5}},
			wantAccountsToConsolidate: []int64{},
			wantPaymentReqs:           []int64{5, 5, 5, 5},
			wantSplitAccountStats:     stats.TransferCount{Count: 4, Amount: 5 + 10 + 10 + 15, Credits: 8},
			wantPaymentRequestStats:   stats.TransferCount{Count: 4, Amount: 5 + 5 + 5 + 5, Credits: 4},
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			wp := runWorkPoolWhile(t)

			_, bb := wtest.NewBlindBank(t)

			accounts := wtest.SeedAccounts(t, bb, 0, tc.accounts...)
			paymentReqs := paymentRequests(t, tc.paymentReqs...)

			stats := pipeline.NewPrefetchWithdrawStats()
			prefetchVal := test.Must(currency.Exact(tc.prefetchAmount))
			outBatchesToConsolidate := work.NewChannel[*transfer.BankBatch]("outBatchesToConsolidate", 0)
			outAccountsToConsolidate := work.NewChannel[*transfer.Account]("outAccountsToConsolidate", 0)
			steps := pipeline.NewPrefetchWithdrawSteps(&pipeline.PrefetchWithdrawSteps{
				ID:       "test",
				Stats:    stats,
				WorkPool: wp,
				BankBatchFunc: func(ctx context.Context) (*transfer.BankBatch, error) {
					return transfer.EmptyBankBatch(), nil
				},
				MaxParallelBankBatches:         1,
				MaxExpiryDuration:              8 * time.Hour,
				PrefetchAmount:                 prefetchVal,
				InputAccounts:                  produce(accounts...),
				InputRequests:                  produce(paymentReqs...),
				OutputBankBatchesToConsolidate: outBatchesToConsolidate,
				OutputAccountsToConsolidate:    outAccountsToConsolidate,
			})

			runSteps(t, steps...)

			// receive payments responses concurrently
			respCh := receivePaymentResponses(paymentReqs...)

			// drain batches and accounts.
			gotBatches, gotAccounts := drain2(outBatchesToConsolidate.ReceiveCh, outAccountsToConsolidate.ReceiveCh)

			require.ElementsMatch(t, tc.wantPaymentReqs, <-respCh)
			requireBankBatches(t, tc.wantBatchesToConsolidate, gotBatches...)
			requireAccountBalances(t, bb, tc.wantAccountsToConsolidate, gotAccounts...)

			require.Equal(t, tc.wantSplitAccountStats, stats.SplitAccounts.Read())
			require.Equal(t, tc.wantPaymentRequestStats, stats.PaymentRequests.Read())
		})
	}

	t.Run("ok, expiring batches are consolidated", func(t *testing.T) {
		t.Parallel()
		wp := runWorkPoolWhile(t)

		_, bb := wtest.NewBlindBank(t)

		stats := &pipeline.PrefetchWithdrawStats{
			SplitAccounts:   stats.NewTransferCounter(),
			PaymentRequests: stats.NewTransferCounter(),
		}

		accounts := wtest.SeedAccounts(t, bb, 0, 10, 15)
		prefetchVal := test.Must(currency.Exact(5))
		inPaymentReqs := make(chan *transfer.PaymentRequest)
		inAccounts := make(chan *transfer.Account)
		outBatchesToConsolidate := work.NewChannel[*transfer.BankBatch]("outBatchesToConsolidate", 0)
		outAccountsToConsolidate := work.NewChannel[*transfer.Account]("outAccountsToConsolidate", 0)
		steps := pipeline.NewPrefetchWithdrawSteps(&pipeline.PrefetchWithdrawSteps{
			ID:       "test",
			Stats:    stats,
			WorkPool: wp,
			BankBatchFunc: func(ctx context.Context) (*transfer.BankBatch, error) {
				return transfer.EmptyBankBatch(), nil
			},
			MaxParallelBankBatches: 1,
			CacheEvictSignalFunc: func(expiresAt time.Time) <-chan time.Time {
				ch := make(chan time.Time)
				go func() {
					ch <- time.Now()
					close(ch)
				}()
				return ch
			},
			PrefetchAmount:                 prefetchVal,
			InputAccounts:                  inAccounts,
			InputRequests:                  inPaymentReqs,
			OutputBankBatchesToConsolidate: outBatchesToConsolidate,
			OutputAccountsToConsolidate:    outAccountsToConsolidate,
		})

		runSteps(t, steps...)

		gotBatches := make(chan []*transfer.BankBatch, 2)
		go func() {
			got := make([]*transfer.BankBatch, 0)
			for range len(accounts) {
				got = append(got, <-outBatchesToConsolidate.ReceiveCh)
			}

			// close inputs, we only expect two batches.
			close(inPaymentReqs)
			close(inAccounts)
			gotBatches <- got
		}()

		inAccounts <- accounts[0]
		inAccounts <- accounts[1]

		gotAccounts := drain(outAccountsToConsolidate.ReceiveCh)

		requireBankBatches(t, []batch{{5, 5}, {5, 5, 5}}, <-gotBatches...)
		requireAccountBalances(t, bb, []int64{}, gotAccounts...)
	})
}
