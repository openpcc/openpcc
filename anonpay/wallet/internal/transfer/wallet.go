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
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/openpcc/openpcc/anonpay"
	"github.com/openpcc/openpcc/anonpay/currency"
)

type PaymentResponse struct {
	Credit *anonpay.BlindedCredit
	Err    error
}

// PaymentRequest is an request from the wallet to provide a credit to the user.
// It bridges gap between the user, wallet and pipeline.
//
// A PaymentRequest is followed by a PaymentResult to complete the entire payment.
//
// See docs_diagram.go in the wallet package for a detailed sequence diagram.
type PaymentRequest struct {
	desiredAmount currency.Value
	stack         *creditStack
	response      chan PaymentResponse
}

func NewPaymentRequest(desiredAmount currency.Value) *PaymentRequest {
	return &PaymentRequest{
		desiredAmount: desiredAmount,
		stack:         newCreditStack(1), // must receive 1 credit.
		response:      make(chan PaymentResponse),
	}
}

func (r *PaymentRequest) DesiredAmount() currency.Value {
	return r.desiredAmount
}

func (*PaymentRequest) maxDelay() time.Duration {
	// no delays required, no external services.
	return 0
}

func (*PaymentRequest) allowedOrigins() []creditOrigin {
	// Payment requests can only receive credits from the blindbank.
	return []creditOrigin{blindbankOrigin}
}

func (r *PaymentRequest) deposit(ctx context.Context, transferID []byte, creds ...*anonpay.BlindedCredit) error {
	var resp PaymentResponse
	resp.Err = r.stack.deposit(ctx, transferID, creds...)
	if len(creds) > 0 {
		resp.Credit = creds[0]
	}
	r.response <- resp
	return resp.Err
}

// ErrPaymentRequestNoWorker is a sentinel error indicating a payment request failed due to
// to the relevant worker shutting down.
var ErrPaymentRequestNoWorker = errors.New("payment request failed, no worker is available")

func (r *PaymentRequest) FailNoWorker() {
	select {
	case r.response <- PaymentResponse{Err: ErrPaymentRequestNoWorker}:
	default:
		return
	}
}

func (r *PaymentRequest) Response() <-chan PaymentResponse {
	return r.response
}

// PaymentResult marks the completion of a payment. Both succesful payments and cancelled payments are modelled
// using payment results, the difference will be in what credits are remaining. A successful payment will have
// unspend credits returned from the paid API and a cancelled payment will have a result containing the original
// credit from the CreditRequest.
//
// The PaymentResult will always exchange remaining credits with the blind bank before they are withdrawn. This is
// required because the remaining credits will either be unblinded credits (for successful payments), or may have
// been exposed to the paid API (for cancelled payments).
//
// See docs_diagram.go in the wallet package for a detailed sequence diagram.
type PaymentResult struct {
	mu        *sync.Mutex
	bank      *BlindBank
	unspend   anonpay.AnyCredit
	exchanged *anonpay.BlindedCredit
	delay     time.Duration
}

func NewPaymentResult(bank *BlindBank, credit anonpay.AnyCredit, maxDelay time.Duration) (*PaymentResult, error) {
	if credit == nil {
		return nil, errors.New("can't create payment result with a nil credit")
	}

	// validate this isn't a special credit.
	_, err := credit.Value().Amount()
	if err != nil {
		return nil, fmt.Errorf("not a regular credit: %w", err)
	}

	return &PaymentResult{
		mu:      &sync.Mutex{},
		bank:    bank,
		unspend: credit,
		delay:   maxDelay,
	}, nil
}

func (d *PaymentResult) Balance() int64 {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.unspend == nil {
		return 0
	}

	return d.unspend.Value().AmountOrZero()
}

func (d *PaymentResult) maxDelay() time.Duration {
	// no delays required, no external services.
	return d.delay
}

func (*PaymentResult) origin() creditOrigin {
	// while the original credit comes from the user, the credits returned
	// from withdraw are coming from the blindbank.
	return blindbankOrigin
}

func (d *PaymentResult) withdraw(ctx context.Context, id []byte, w Withdrawal) ([]*anonpay.BlindedCredit, int64, error) {
	d.mu.Lock()
	defer d.mu.Unlock()

	if w != FullWithdrawal {
		want := w.Amount.AmountOrZero()
		got := d.unspend.Value().AmountOrZero()
		if w.Credits != 1 || want != got {
			return nil, 0, WithdrawalError{
				Err: anonpay.CreditsNotAvailableError{
					Amount: d.unspend.Value(),
				},
				Withdrawal: w,
			}
		}
	}

	if d.exchanged != nil {
		return nil, 0, WithdrawalError{
			Err:        errors.New("payment result already withdrawn"),
			Withdrawal: w,
		}
	}

	exchanged, err := d.bank.Exchange(ctx, id, d.unspend)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to exchange credit: %w", err)
	}

	d.exchanged = exchanged

	return []*anonpay.BlindedCredit{d.exchanged}, 0, nil
}
