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

package transfer

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"slices"
	"sync"
	"time"

	"github.com/openpcc/openpcc/anonpay"
	"github.com/openpcc/openpcc/anonpay/currency"
)

// BankBatch is a batch of one or more credits received from the bank. Can
// receive a single deposit of one or more bank credits.
type BankBatch struct {
	*creditStack
}

func EmptyBankBatch() *BankBatch {
	return &BankBatch{newCreditStack(0)}
}

func (*BankBatch) maxDelay() time.Duration {
	// no delays required, no external services.
	return 0
}

func (*BankBatch) origin() creditOrigin {
	return blindbankOrigin
}

func (*BankBatch) allowedOrigins() []creditOrigin {
	// Bank batches can only receive credits from the blindbank.
	return []creditOrigin{blindbankOrigin}
}

// creditStack is a stack of one or more credits of the same amount that are stored
// in memory. The creditStack is wrapped by more specific types that represent concrete
// withdrawables/depositables.
//
// A creditStack can only be deposited to once, if multiple credits are deposited they
// must all be of the same amount.
//
// A credt stack's lifetime ends once its last credit is withdrawn.
type creditStack struct {
	mu                *sync.Mutex
	depositTransferID []byte
	maxCredits        int
	credits           []*anonpay.BlindedCredit
	creditAmount      currency.Value
}

func newCreditStack(maxCredits int) *creditStack {
	return &creditStack{
		mu:                &sync.Mutex{},
		depositTransferID: nil,
		maxCredits:        maxCredits,
		credits:           nil,
	}
}

func (s *creditStack) ID() []byte {
	return bytes.Clone(s.depositTransferID)
}

func (s *creditStack) NumCredits() int {
	s.mu.Lock()
	defer s.mu.Unlock()

	return len(s.credits)
}

func (s *creditStack) CreditAmount() currency.Value {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.creditAmount
}

func (s *creditStack) Balance() int64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return int64(len(s.credits)) * s.creditAmount.AmountOrZero()
}

func (s *creditStack) ExpiresAt() time.Time {
	s.mu.Lock()
	defer s.mu.Unlock()
	var lowestTimestamp int64
	for i, credit := range s.credits {
		if i == 0 || credit.Nonce().Timestamp < lowestTimestamp {
			lowestTimestamp = credit.Nonce().Timestamp
		}
	}

	return time.Unix(lowestTimestamp, 0)
}

func (s *creditStack) canWithdrawNoLock(w Withdrawal) bool {
	if len(s.credits) == 0 {
		return false
	}

	if w == FullWithdrawal {
		return true
	}

	if s.creditAmount != w.Amount {
		return false
	}

	if len(s.credits) < w.Credits {
		return false
	}

	return true
}

func (s *creditStack) deposit(_ context.Context, transferID []byte, credits ...*anonpay.BlindedCredit) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.depositTransferID) != 0 {
		return errors.New("credit stack can't receive a second deposit")
	}

	if len(credits) == 0 {
		return errors.New("credit stack can't receive empty deposits")
	}

	if s.maxCredits != 0 && len(credits) > s.maxCredits {
		return fmt.Errorf("received deposit of %d credits, can at maximum contain %d credits", len(credits), s.maxCredits)
	}

	s.depositTransferID = bytes.Clone(transferID)
	s.credits = credits
	s.creditAmount = credits[0].Value()
	return nil
}

// withdraw implements the Withdrawable interface. creditStack only uses the Withdrawal though.
func (s *creditStack) withdraw(_ context.Context, _ []byte, w Withdrawal) ([]*anonpay.BlindedCredit, int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.canWithdrawNoLock(w) {
		return nil, 0, WithdrawalError{
			Withdrawal: w,
			Err: anonpay.CreditsNotAvailableError{
				Credits: len(s.credits),
				Amount:  s.creditAmount,
			},
		}
	}

	i := w.Credits
	if w == FullWithdrawal {
		i = len(s.credits)
	}
	out := slices.Clone(s.credits[:i])
	remaining := s.credits[i:]

	s.credits = remaining

	return out, 0, nil
}
