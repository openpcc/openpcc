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

package test

import (
	"fmt"
	"testing"
	"time"

	"github.com/openpcc/openpcc/anonpay/banking"
	"github.com/openpcc/openpcc/anonpay/banking/inmem"
	"github.com/openpcc/openpcc/anonpay/currency"
	"github.com/openpcc/openpcc/anonpay/wallet/internal/transfer"
	"github.com/openpcc/openpcc/internal/test/anonpaytest"
	"github.com/stretchr/testify/require"
)

type RoundedCurrencyFunc func(signedAmount uint64) (currency.Value, error)

func NewBlindBank(t *testing.T) (*inmem.Bank, *transfer.BlindBank) {
	issuer := anonpaytest.MustNewIssuer()
	payee := anonpaytest.MustNewPayee()
	srcBank := inmem.NewBankWithRoundFunc(issuer, &anonpaytest.NoopNonceLocker{}, func(signedAmount uint64) (currency.Value, error) {
		// always round down in this test case for consistent results.
		return currency.RoundedInt(signedAmount, 0)
	})
	return srcBank, transfer.NewBlindBank(payee, srcBank)
}

func SeedAccounts(t *testing.T, b *transfer.BlindBank, maxDelay time.Duration, balances ...int64) []*transfer.Account {
	out := []*transfer.Account{}
	for _, balance := range balances {
		account, err := banking.GenerateAccountToken()
		require.NoError(t, err)

		transferID, err := transfer.GenerateID()
		require.NoError(t, err)
		vals, err := splitBalanceExact(balance)
		require.NoError(t, err)

		for _, val := range vals {
			credit := anonpaytest.MustBlindCredit(t.Context(), val)
			_, err = b.Deposit(t.Context(), transferID, account, credit)
			require.NoError(t, err)
		}

		acc, err := transfer.RestoreBankAccount(t.Context(), b, account, balance, maxDelay)
		require.NoError(t, err)
		out = append(out, acc)
	}
	return out
}

//type BlindBank struct {
//	WithdrawBatchFunc   func(ctx context.Context, transferID []byte, account banking.AccountToken, credits int, amount currency.Value) (int64, []*anonpay.BlindedCredit, error)
//	WithdrawFullFunc    func(ctx context.Context, transferID []byte, account banking.AccountToken) (*anonpay.UnblindedCredit, error)
//	DepositFunc         func(ctx context.Context, transferID []byte, account banking.AccountToken, creds ...*anonpay.BlindedCredit) (int64, error)
//	ExchangeFunc        func(ctx context.Context, transferID []byte, credit anonpay.AnyCredit) (*anonpay.BlindedCredit, error)
//	RoundedCurrencyFunc RoundedCurrencyFunc
//
//	t             *testing.T
//	mu            *sync.Mutex
//	nextAccountID int64
//	accounts      map[int64]*account
//}
//
//func NewBlindBank(t *testing.T) *BlindBank {
//	return &BlindBank{
//		t:             t,
//		mu:            &sync.Mutex{},
//		nextAccountID: 0,
//		accounts:      make(map[int64]*account),
//	}
//}
//
//func (*BlindBank) accountTokenToKey(account banking.AccountToken) (int64, error) {
//	return strconv.ParseInt(string(account.SecretBytes()), 10, 64)
//}
//
//func (b *BlindBank) WithdrawBatch(ctx context.Context, transferID []byte, account banking.AccountToken, n int, amount currency.Value) (int64, []*anonpay.BlindedCredit, error) {
//	if b.WithdrawBatchFunc != nil {
//		return b.WithdrawBatchFunc(ctx, transferID, account, n, amount)
//	}
//
//	b.mu.Lock()
//	defer b.mu.Unlock()
//
//	key, err := b.accountTokenToKey(account)
//	if err != nil {
//		return 0, nil, fmt.Errorf("failed to parse account: %w", err)
//	}
//
//	acc, ok := b.accounts[key]
//	if !ok {
//		return 0, nil, errors.New("unknown account")
//	}
//
//	credits, err := acc.withdraw(b.t, n, amount)
//	if err != nil {
//		return 0, nil, err
//	}
//
//	return acc.balance, credits, nil
//}
//
//func (b *BlindBank) WithdrawFullUnblinded(ctx context.Context, transferID []byte, account banking.AccountToken) (*anonpay.UnblindedCredit, error) {
//	if b.WithdrawFullFunc != nil {
//		return b.WithdrawFullFunc(ctx, transferID, account)
//	}
//
//	b.mu.Lock()
//	defer b.mu.Unlock()
//
//	key, err := b.accountTokenToKey(account)
//	if err != nil {
//		return nil, fmt.Errorf("failed to parse account: %w", err)
//	}
//
//	acc, ok := b.accounts[key]
//	if !ok {
//		return nil, fmt.Errorf("unknown account %s", account)
//	}
//
//	roundedFunc := b.RoundedCurrencyFunc
//	if roundedFunc == nil {
//		roundedFunc = func(signedAmount float64) (currency.Value, error) {
//			roundingFactor, err := currency.RandFloat64()
//			if err != nil {
//				return currency.Value{}, fmt.Errorf("could not create random rounding factor: %w", err)
//			}
//			return currency.Rounded(signedAmount, roundingFactor)
//		}
//	}
//
//	return acc.withdrawFull(b.t, roundedFunc)
//}
//
//func (b *BlindBank) Deposit(ctx context.Context, transferID []byte, account banking.AccountToken, credits ...*anonpay.BlindedCredit) (int64, error) {
//	if b.DepositFunc != nil {
//		return b.DepositFunc(ctx, transferID, account, credits...)
//	}
//
//	return b.depositCredits(account, credits...)
//}
//
//func (b *BlindBank) depositCredits(accountToken banking.AccountToken, credits ...*anonpay.BlindedCredit) (int64, error) {
//	b.mu.Lock()
//	defer b.mu.Unlock()
//
//	key, err := b.accountTokenToKey(accountToken)
//	if err != nil {
//		return 0, fmt.Errorf("failed to parse account: %w", err)
//	}
//
//	acc, ok := b.accounts[key]
//	if !ok {
//		acc = &account{}
//		b.accounts[key] = acc
//	}
//
//	err = acc.deposit(credits...)
//	if err != nil {
//		return 0, err
//	}
//
//	return acc.balance, nil
//}
//
//func (b *BlindBank) Exchange(ctx context.Context, transferID []byte, credit anonpay.AnyCredit) (*anonpay.BlindedCredit, error) {
//	if b.ExchangeFunc != nil {
//		return b.ExchangeFunc(ctx, transferID, credit)
//	}
//
//	return anonpaytest.MustBlindCredit(b.t.Context(), credit.Value()), nil
//}
//
//func (b *BlindBank) HelperNewAccounts(maxDelay time.Duration, balances ...int64) []*transfer.Account {
//	out := []*transfer.Account{}
//	for _, balance := range balances {
//		account, err := banking.GenerateAccountToken()
//		require.NoError(b.t, err)
//
//		transferID, err := transfer.GenerateID()
//		require.NoError(b.t, err)
//
//		vals, err := splitBalanceExact(balance)
//		require.NoError(b.t, err)
//		for _, val := range vals {
//			credit := anonpaytest.MustBlindCredit(b.t.Context(), val)
//			_, err = b.Deposit(b.t.Context(), transferID, account, credit)
//			require.NoError(b.t, err)
//		}
//
//		acc, err := transfer.RestoreBankAccount(b.t.Context(), b, account, balance, maxDelay)
//		require.NoError(b.t, err)
//
//		out = append(out, acc)
//	}
//	return out
//}
//
//// HelperAccountState is a test helper method to get the state for an account.
//func (b *BlindBank) HelperAccountState(account banking.AccountToken) (int64, []int64) {
//	b.t.Helper()
//
//	b.mu.Lock()
//	defer b.mu.Unlock()
//
//	key, err := b.accountTokenToKey(account)
//	require.NoError(b.t, err)
//
//	acc, ok := b.accounts[key]
//	if !ok {
//		require.Fail(b.t, "unknown account")
//	}
//
//	return acc.balance, slices.Clone(acc.mutations)
//}
//
//func (b *BlindBank) HelperTotalBalance() int64 {
//	b.t.Helper()
//
//	b.mu.Lock()
//	defer b.mu.Unlock()
//
//	sum := int64(0)
//	for _, acc := range b.accounts {
//		sum += acc.balance
//	}
//	return sum
//}
//
//func (b *BlindBank) HelperTotalRoundingGains() int64 {
//	b.t.Helper()
//
//	b.mu.Lock()
//	defer b.mu.Unlock()
//
//	sum := int64(0)
//	for _, acc := range b.accounts {
//		for _, diff := range acc.roundingGains {
//			sum += diff
//		}
//	}
//	return sum
//}

func splitBalanceExact(signedAmount int64) ([]currency.Value, error) {
	if signedAmount < 0 {
		return nil, currency.ErrNegativeUnrepresentable
	}

	var out []currency.Value
	remaining := signedAmount
	for remaining > 0 {
		n := min(remaining, currency.MaxAmount)
		val, err := currency.RoundedInt(uint64(n), 0)
		if err != nil {
			return nil, fmt.Errorf("failed to round %d down", n)
		}

		remaining -= val.AmountOrZero()
		out = append(out, val)
	}
	return out, nil
}
