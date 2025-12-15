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

package wallet_test

import (
	"context"
	"fmt"
	"slices"
	"sync/atomic"
	"testing"
	"time"

	"github.com/openpcc/openpcc/anonpay"
	"github.com/openpcc/openpcc/anonpay/banking/inmem"
	"github.com/openpcc/openpcc/anonpay/currency"
	"github.com/openpcc/openpcc/anonpay/wallet"
	wtest "github.com/openpcc/openpcc/anonpay/wallet/internal/test"
	"github.com/openpcc/openpcc/internal/test/anonpaytest"
	test "github.com/openpcc/openpcc/inttest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sync/errgroup"
)

func TestWalletPayments(t *testing.T) {
	tests := map[string]struct {
		startSourceBalance int64
		// note: positive integers will be successful, negative
		// integers will be cancelled (but provided as positive amounts for withdrawals).
		workers            [][]int64
		workFunc           func(t *testing.T, c *anonpay.BlindedCredit) *anonpay.UnblindedCredit
		wantWorkerConsumed int64
		cfg                wallet.Config
	}{
		"ok, no source balance, no payments": {
			startSourceBalance: 0,
			workers:            nil,
			cfg: wallet.Config{
				SourceAmount:       10,
				PrefetchAmount:     10,
				MaxParallel:        1,
				MaxDelay:           time.Millisecond,
				AvgPaymentDuration: 0,
			},
			wantWorkerConsumed: 0,
		},
		"ok, 1 credit source balance, no payments": {
			startSourceBalance: 10,
			workers:            nil,
			cfg: wallet.Config{
				SourceAmount:       10,
				PrefetchAmount:     10,
				MaxParallel:        1,
				MaxDelay:           time.Millisecond,
				AvgPaymentDuration: 0,
			},
			wantWorkerConsumed: 0,
		},
		"ok, large source balance, no payments": {
			startSourceBalance: 10_000_000,
			workers:            nil,
			cfg: wallet.Config{
				SourceAmount:       10,
				PrefetchAmount:     10,
				MaxParallel:        1,
				MaxDelay:           time.Millisecond,
				AvgPaymentDuration: 0,
			},
			wantWorkerConsumed: 0,
		},
		"ok, exact source balance, 1 payment, successful": {
			startSourceBalance: 10,
			workers:            [][]int64{{10}},
			cfg: wallet.Config{
				SourceAmount:       10,
				PrefetchAmount:     10,
				MaxParallel:        1,
				MaxDelay:           time.Millisecond,
				AvgPaymentDuration: 0,
			},
			wantWorkerConsumed: 10,
		},
		"ok, exact source balance, 1 payment, successful, full refund": {
			startSourceBalance: 10,
			workers:            [][]int64{{10}},
			workFunc: func(t *testing.T, c *anonpay.BlindedCredit) *anonpay.UnblindedCredit {
				return anonpaytest.MustUnblindCredit(t.Context(), c.Value())
			},
			cfg: wallet.Config{
				SourceAmount:       10,
				PrefetchAmount:     10,
				MaxParallel:        1,
				MaxDelay:           time.Millisecond,
				AvgPaymentDuration: 0,
			},
			wantWorkerConsumed: 0,
		},
		"ok, exact source balance, 1 payment, cancelled": {
			startSourceBalance: 10,
			workers:            [][]int64{{-10}},
			cfg: wallet.Config{
				SourceAmount:       10,
				PrefetchAmount:     10,
				MaxParallel:        1,
				MaxDelay:           time.Millisecond,
				AvgPaymentDuration: 0,
			},
			wantWorkerConsumed: 0,
		},
		"ok, exact source balance, many workers": {
			startSourceBalance: 100 * 10, //exactly enough to fullfil 100 credits
			workers: [][]int64{
				slices.Repeat([]int64{10}, 20),
				slices.Repeat([]int64{10}, 20),
				slices.Repeat([]int64{10}, 20),
				slices.Repeat([]int64{10}, 20),
				slices.Repeat([]int64{10}, 20),
			},
			cfg: wallet.Config{
				SourceAmount:       100,
				PrefetchAmount:     10,
				MaxParallel:        5,
				MaxDelay:           time.Millisecond,
				AvgPaymentDuration: 0,
			},
			wantWorkerConsumed: 100 * 10,
		},
		"ok, 500 withdrawals, mix of cancellations and successes, no unspend credits": {
			startSourceBalance: 10_000_000,
			workers: [][]int64{
				slices.Repeat([]int64{10, 10, 10, 10, -10}, 20), // 100 credits
				slices.Repeat([]int64{10, 10, 10, -10, 10}, 20),
				slices.Repeat([]int64{10, 10, -10, 10, 10}, 20),
				slices.Repeat([]int64{10, -10, 10, 10, 10}, 20),
				slices.Repeat([]int64{-10, 10, 10, 10, 10}, 20),
			},
			cfg: wallet.Config{
				SourceAmount:       100,
				PrefetchAmount:     10,
				MaxParallel:        5,
				MaxDelay:           time.Millisecond,
				AvgPaymentDuration: 0,
			},
			wantWorkerConsumed: 4000, // 20% of payments was cancelled.
		},
		"ok, 500 withdrawals, half unspend": {
			startSourceBalance: 10_000_000,
			workers: [][]int64{
				slices.Repeat([]int64{10, 10, 10, 10, 10}, 20),
				slices.Repeat([]int64{10, 10, 10, 10, 10}, 20),
				slices.Repeat([]int64{10, 10, 10, 10, 10}, 20),
				slices.Repeat([]int64{10, 10, 10, 10, 10}, 20),
				slices.Repeat([]int64{10, 10, 10, 10, 10}, 20),
			},
			workFunc: func(t *testing.T, c *anonpay.BlindedCredit) *anonpay.UnblindedCredit {
				value := test.Must(currency.Rounded(float64(c.Value().AmountOrZero()/2), 0.0))
				return anonpaytest.MustUnblindCredit(t.Context(), value)
			},
			cfg: wallet.Config{
				SourceAmount:       100,
				PrefetchAmount:     10,
				MaxParallel:        5,
				MaxDelay:           time.Millisecond,
				AvgPaymentDuration: 0,
			},
			wantWorkerConsumed: 2500,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			inMemBank, _ := wtest.NewBlindBank(t)
			env := &environment{
				src: wtest.NewSource(t, tc.startSourceBalance),
				bb:  inMemBank,
			}

			payee := anonpaytest.MustNewPayee()
			w, err := wallet.New(tc.cfg, payee, env.bb, env.src)
			require.NoError(t, err)
			env.w = w

			t.Cleanup(func() {
				// we'll close it in the main test later, but it should
				// be fine to close again as part of the cleanup in case the test fails.
				err = w.Close(t.Context())
				require.NoError(t, err)
			})

			workerConsumed := &atomic.Int64{}

			// run workers that withdraw the requests.
			g, gCtx := errgroup.WithContext(t.Context())
			for workerIdx, worker := range tc.workers {
				g.Go(func() error {
					for i, amount := range worker {
						success := amount > 0
						if !success {
							amount *= -1
						}
						payment, err := w.BeginPayment(gCtx, amount)
						if err != nil {
							return fmt.Errorf("withdrawal %d of %d failed in worker %d: %w", i, amount, workerIdx, err)
						}

						time.Sleep(tc.cfg.AvgPaymentDuration)
						var unspend *anonpay.UnblindedCredit
						consumed := payment.Credit().Value().AmountOrZero()
						if tc.workFunc != nil {
							unspend = tc.workFunc(t, payment.Credit())
							consumed -= unspend.Value().AmountOrZero()
						}

						if success {
							workerConsumed.Add(consumed)
							err = payment.Success(unspend)
						} else {
							// cancel the payment
							err = payment.Cancel()
						}
						if err != nil {
							return fmt.Errorf("failed to complete payment: %w", err)
						}
					}
					return nil
				})
			}

			err = g.Wait()
			require.NoError(t, err)

			// close the wallet.
			err = w.Close(t.Context())
			require.NoError(t, err)
			env.consumed = workerConsumed.Load()

			requireEnvironment(t, env, tc.wantWorkerConsumed)
		})
	}
}

func TestWalletErrorHandling(t *testing.T) {
	requireWalletClosedError := func(t *testing.T, err error) {
		t.Helper()

		require.ErrorIs(t, err, assert.AnError)
		closedErr := wallet.ClosedError{}
		require.ErrorAs(t, err, &closedErr)
		require.False(t, closedErr.CloseCalled())
		require.True(t, closedErr.InternalError())
	}

	serviceErrors := map[string]struct {
		setupSource            func(src *wtest.FailingSource)
		setupBank              func(bb *wtest.FailingBlindBank)
		paymentFunc            func(i int, p wallet.Payment) error
		requirePaymentFailures bool
	}{
		"fail, source.Withdraw never works": {
			setupSource: func(src *wtest.FailingSource) {
				src.FailWithdrawAfter = 0
			},
			requirePaymentFailures: true,
		},
		"fail, source.Withdraw fails after some requests": {
			setupSource: func(src *wtest.FailingSource) {
				src.FailWithdrawAfter = 50
			},
			requirePaymentFailures: true,
		},
		"fail, source.Deposit never works": {
			setupSource: func(src *wtest.FailingSource) {
				src.FailDepositAfter = 0
			},
			// while this failing could eventually lead to payment failures,
			// it's difficult to trigger this in tests.
			requirePaymentFailures: false,
		},
		"fail, source.Deposit fails after some requests": {
			setupSource: func(src *wtest.FailingSource) {
				src.FailDepositAfter = 50
			},
			// while this failing could eventually lead to payment failures,
			// it's difficult to trigger this in tests.
			requirePaymentFailures: false,
		},
		"fail, bank.WithdrawBatch never works": {
			setupBank: func(src *wtest.FailingBlindBank) {
				src.FailWithdrawBatchAfter = 0
			},
			requirePaymentFailures: true,
		},
		"fail, bank.WithdrawBatch fails after some requests": {
			setupBank: func(src *wtest.FailingBlindBank) {
				src.FailWithdrawBatchAfter = 50
			},
			requirePaymentFailures: true,
		},
		"fail, bank.WithdrawFullUnblinded never works": {
			setupBank: func(src *wtest.FailingBlindBank) {
				src.FailWithrawFullUnblindedAfter = 0
			},
			// while this failing could eventually lead to payment failures,
			// it's difficult to trigger this in tests.
			requirePaymentFailures: false,
		},
		"fail, bank.WithdrawFullUnblinded fails after some requests": {
			setupBank: func(src *wtest.FailingBlindBank) {
				src.FailWithrawFullUnblindedAfter = 50
			},
			// while this failing could eventually lead to payment failures,
			// it's difficult to trigger this in tests.
			requirePaymentFailures: false,
		},
		"fail, bank.Deposit never works": {
			setupBank: func(src *wtest.FailingBlindBank) {
				src.FailDepositAfter = 0
			},
			requirePaymentFailures: true,
		},
		"fail, bank.Deposit fails after some requests": {
			setupBank: func(src *wtest.FailingBlindBank) {
				src.FailDepositAfter = 50
			},
			requirePaymentFailures: true,
		},
		"fail, bank.Exchange never works": {
			setupBank: func(src *wtest.FailingBlindBank) {
				src.FailExchangeAfter = 0
			},
			requirePaymentFailures: true,
		},
		"fail, bank.Exchange fails after some requests": {
			setupBank: func(src *wtest.FailingBlindBank) {
				src.FailExchangeAfter = 50
			},
			requirePaymentFailures: true,
		},
	}

	for name, tc := range serviceErrors {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			src := wtest.NewFailingSource(t, 10_000_000)
			if tc.setupSource != nil {
				tc.setupSource(src)
			}
			bb := wtest.NewFailingBlindBank(t)
			if tc.setupBank != nil {
				tc.setupBank(bb)
			}

			payee := anonpaytest.MustNewPayee()

			// setup the wallet
			cfg := wallet.Config{
				SourceAmount:   100,
				PrefetchAmount: 10,
				MaxParallel:    2,
				MaxDelay:       1 * time.Millisecond,
			}
			w, err := wallet.New(cfg, payee, bb, src)
			require.NoError(t, err)

			// bit of a hack, but we need to wait for the first wallet delays to pass
			time.Sleep(time.Millisecond * 100)

			t.Cleanup(func() {
				// use a new context because t.Context provided will have been cancelled by now.
				ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
				defer cancel()

				err = w.Close(ctx)
				// ensure the root error is included as part of this output.
				require.ErrorIs(t, err, assert.AnError)
			})

			paymentFunc := func(i int, p wallet.Payment) error {
				switch i % 3 {
				case 1:
					return p.Success(nil)
				case 2:
					value := test.Must(currency.Exact(cfg.PrefetchAmount / 2))
					cred := anonpaytest.MustUnblindCredit(t.Context(), value)
					return p.Success(cred)
				default:
					return p.Cancel()
				}
			}

			if tc.paymentFunc != nil {
				paymentFunc = tc.paymentFunc
			}

			failedAPayment := false
			for i := range 1000 {
				payment, err := w.BeginPayment(t.Context(), cfg.PrefetchAmount)
				if err == nil {
					err = paymentFunc(i, payment)
				}

				// err != nil because not all payments will necessary fail,
				// we just want at least one of them to fail.
				if err != nil {
					requireWalletClosedError(t, err)
					failedAPayment = true
					break
				}

				require.NoError(t, err)
			}

			if tc.requirePaymentFailures {
				require.True(t, failedAPayment)
			}
		})
	}

	t.Run("fail, context cancelled while waiting for payment to begin", func(t *testing.T) {
		origSrc := wtest.NewSource(t, 10)
		// wrap to source and only begin making credits available after the given channel is
		// received from so that we can't accidentally fullfil the payment.
		done := make(chan struct{})
		wSrc := wtest.NewSource(t, 0)
		wSrc.WithdrawFunc = func(ctx context.Context, transferID []byte, amount currency.Value) (*anonpay.BlindedCredit, error) {
			<-done
			return origSrc.Withdraw(ctx, transferID, amount)
		}
		wSrc.DepositFunc = origSrc.Deposit

		payee := anonpaytest.MustNewPayee()
		inMemBank, _ := wtest.NewBlindBank(t)
		env := &environment{
			bb:  inMemBank,
			src: origSrc,
		}

		// setup the wallet
		cfg := wallet.Config{
			SourceAmount:   10,
			PrefetchAmount: 10,
			MaxParallel:    1,
			MaxDelay:       10 * time.Millisecond,
		}
		w, err := wallet.New(cfg, payee, env.bb, wSrc)
		require.NoError(t, err)
		env.w = w

		t.Cleanup(func() {
			// we'll close it in the main test later, but it should
			// be fine to close again as part of the cleanup in case the test fails.
			err = w.Close(t.Context())
			require.NoError(t, err)
		})

		// context will get cancelled when the first amount is withdrawn from the bank.
		paymentCtx, cancelCtx := context.WithCancel(t.Context())

		go func() {
			time.Sleep(10 * time.Millisecond)
			cancelCtx()
		}()

		_, err = w.BeginPayment(paymentCtx, 10)
		require.ErrorIs(t, err, context.Canceled)

		// allow the withdraw to return
		close(done)

		// close the wallet.
		err = w.Close(t.Context())
		require.NoError(t, err)

		requireEnvironment(t, env, 0)
	})

	t.Run("fail, hard exit, close context cancelled", func(t *testing.T) {
		payee := anonpaytest.MustNewPayee()
		inMemBank, _ := wtest.NewBlindBank(t)
		env := &environment{
			bb:  inMemBank,
			src: wtest.NewSource(t, 1000),
		}

		closeCtx, closeCtxCancel := context.WithCancelCause(t.Context())
		env.src.DepositFunc = func(ctx context.Context, transferID []byte, credits ...*anonpay.BlindedCredit) error {
			closeCtxCancel(nil)
			return nil
		}

		// setup the wallet
		cfg := wallet.Config{
			SourceAmount:   100,
			PrefetchAmount: 10,
			MaxParallel:    1,
			MaxDelay:       time.Millisecond * 5,
		}
		w, err := wallet.New(cfg, payee, env.bb, env.src)
		require.NoError(t, err)

		// give the pipeline some time to process the credits.
		time.Sleep(100 * time.Millisecond)

		// close the wallet, the first return to source will trigger the context to be cancelled.
		err = w.Close(closeCtx)
		require.Error(t, err)

		// environment is in an indeterminate state now.
	})
}

type environment struct {
	w        *wallet.Wallet
	bb       *inmem.Bank
	src      *wtest.Source
	consumed int64
}

func requireEnvironment(t *testing.T, env *environment, wantConsumed int64) {
	// all accounts should have been returned to source.
	require.Equal(t, int64(0), env.bb.TotalBalance())

	require.Equal(t, wantConsumed, env.consumed)

	// verify the wallet status
	require.Equal(t, wallet.Status{
		CreditsSpent:     env.consumed,
		CreditsHeld:      0,
		CreditsAvailable: 0,
	}, env.w.Status())

	// account for any rounding differences introduced by the blindbank.
	wantBalance := env.src.TestInitialBalance() - (env.consumed - roundingGain(env.bb))

	srcBalance, _ := env.src.TestState()
	require.Equal(t, wantBalance, srcBalance)
}

func roundingGain(bb *inmem.Bank) int64 {
	gain := int64(0)
	for _, mutation := range bb.RoundingMutations() {
		// mutations are from the bank perspective, so negatives
		// are gains for the user.
		gain += -1 * mutation
	}

	return gain
}
