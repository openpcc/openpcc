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

	"github.com/openpcc/openpcc/anonpay"
	"github.com/openpcc/openpcc/anonpay/currency"
	"github.com/openpcc/openpcc/anonpay/wallet/internal/transfer"
	"github.com/openpcc/openpcc/internal/test/anonpaytest"
)

type account struct {
	balance       int64
	mutations     []int64
	roundingGains []int64
}

func (a *account) withdraw(t *testing.T, n int, amount currency.Value) ([]*anonpay.BlindedCredit, error) {
	sum := int64(0)
	mutations := make([]int64, 0, n)
	out := make([]*anonpay.BlindedCredit, 0, n)
	for range n {
		credit := anonpaytest.MustBlindCredit(t.Context(), amount)
		sum += amount.AmountOrZero()
		mutations = append(mutations, -amount.AmountOrZero())
		out = append(out, credit)
	}

	if sum > a.balance {
		return nil, transfer.WithdrawalError{
			Withdrawal: transfer.Withdrawal{
				Credits: n,
				Amount:  amount,
			},
			Err: anonpay.InsufficientBalanceError{
				Balance: a.balance,
			},
		}
	}

	a.balance -= sum
	a.mutations = append(a.mutations, mutations...)

	return out, nil
}

func (a *account) deposit(credits ...*anonpay.BlindedCredit) error {
	sum := int64(0)
	mutations := make([]int64, 0, len(credits))
	for _, credit := range credits {
		amount := credit.Value().AmountOrZero()
		if amount < 0 {
			return fmt.Errorf("deposited amount must be positive, got %d", amount)
		}
		sum += amount
		mutations = append(mutations, amount)
	}

	a.balance += sum
	a.mutations = append(a.mutations, mutations...)

	return nil
}
