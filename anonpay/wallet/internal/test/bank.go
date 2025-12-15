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

type RoundedCurrencyFunc func(signedAmount float64) (currency.Value, error)

func NewBlindBank(t *testing.T) (*inmem.Bank, *transfer.BlindBank) {
	issuer := anonpaytest.MustNewIssuer()
	payee := anonpaytest.MustNewPayee()
	srcBank := inmem.NewBankWithRoundFunc(issuer, &anonpaytest.NoopNonceLocker{}, func(signedAmount float64) (currency.Value, error) {
		// always round down in test cases for consistent results.
		return currency.Rounded(signedAmount, 0)
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

func splitBalanceExact(signedAmount int64) ([]currency.Value, error) {
	if signedAmount < 0 {
		return nil, currency.ErrNegativeUnrepresentable
	}

	var out []currency.Value
	remaining := signedAmount
	for remaining > 0 {
		n := min(remaining, currency.MaxAmount)
		val, err := currency.Rounded(float64(n), 0.0)
		if err != nil {
			return nil, fmt.Errorf("failed to round %d down", n)
		}

		remaining -= val.AmountOrZero()
		out = append(out, val)
	}
	return out, nil
}
