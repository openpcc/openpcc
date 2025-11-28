package inmem

import (
	"context"
	"crypto/sha512"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"sync"

	"github.com/openpcc/openpcc/anonpay"
	"github.com/openpcc/openpcc/anonpay/banking"
	"github.com/openpcc/openpcc/anonpay/currency"
)

const maxReqs = 15

var keyHash = sha512.New()

// Bank is an in memory reference implementation of the [BlindBankContract].
type Bank struct {
	mu        *sync.RWMutex
	issuer    *anonpay.Issuer
	processor *anonpay.Processor
	exchanger *anonpay.Exchanger
	accounts  map[string]storedAccount
	roundFunc CurencyRoundFunc

	roundingMutations []int64
}

func NewBank(issuer *anonpay.Issuer, nonceLocker anonpay.NonceLocker) *Bank {
	return NewBankWithRoundFunc(issuer, nonceLocker, func(signedAmount uint64) (currency.Value, error) {
		randVal, err := currency.RandUint53()
		if err != nil {
			return currency.Value{}, fmt.Errorf("failed to get random uint53: %w", err)
		}
		val, err := currency.RoundedInt(signedAmount, randVal)
		if err != nil {
			return currency.Value{}, fmt.Errorf("failed to round currency: %w", err)
		}
		return val, nil
	})
}

type CurencyRoundFunc func(signedAmount uint64) (currency.Value, error)

// NewBankWithRoundFunc allows you to specifiy a custom rounding function used during [WithdrawFullUnblinded],
// useful for when you want to use specific rounding in test cases. Should not be used in production.
func NewBankWithRoundFunc(issuer *anonpay.Issuer, nonceLocker anonpay.NonceLocker, roundFunc CurencyRoundFunc) *Bank {
	return &Bank{
		mu:        &sync.RWMutex{},
		issuer:    issuer,
		processor: anonpay.NewProcessor(issuer, nonceLocker),
		exchanger: anonpay.NewExchanger(issuer, nonceLocker),
		accounts:  make(map[string]storedAccount),
		roundFunc: roundFunc,
	}
}

func (b *Bank) WithdrawBatch(ctx context.Context, _ []byte, account banking.AccountToken, reqs []anonpay.BlindSignRequest) (int64, [][]byte, error) {
	// validate the input requests.
	if len(reqs) == 0 {
		return 0, nil, anonpay.InputError{
			Err: errors.New("can't withdraw zero credits"),
		}
	}
	if len(reqs) > maxReqs {
		return 0, nil, anonpay.InputError{
			Err: fmt.Errorf("can't withdraw more than %d credits, got %d requests", maxReqs, len(reqs)),
		}
	}
	sum := int64(0)
	seen := map[string]struct{}{}
	for _, req := range reqs {
		_, ok := seen[string(req.BlindedMessage)]
		if ok {
			return 0, nil, anonpay.InputError{
				Err: errors.New("duplicate blind sign request"),
			}
		}

		amount, err := req.Value.Amount()
		if err != nil {
			return 0, nil, anonpay.InputError{
				Err: fmt.Errorf("can't withdraw special credit: %w", err),
			}
		}

		if amount <= 0 {
			return 0, nil, anonpay.InputError{
				Err: errors.New("can't withdraw zero amount"),
			}
		}
		sum += amount
		seen[string(req.BlindedMessage)] = struct{}{}
	}

	// blind sign the requests.
	// note: could be done in parallel as long as the original order of requests is preserved.
	blindSignatures := make([][]byte, 0, len(reqs))
	for i, req := range reqs {
		sig, err := b.issuer.BlindSign(ctx, req)
		if err != nil {
			return 0, nil, fmt.Errorf("failed to blind sign request %d: %w", i, err)
		}
		blindSignatures = append(blindSignatures, sig)
	}

	// update the balance in storage.
	b.mu.Lock()
	defer b.mu.Unlock()

	key := keyForAccount(account)
	stored, ok := b.accounts[key] // defaults to 0 if the account isn't in the map.
	if !ok {
		return 0, nil, anonpay.InsufficientBalanceError{
			Balance: 0,
		}
	}
	if stored.balance < sum {
		return 0, nil, anonpay.InsufficientBalanceError{
			Balance: stored.balance,
		}
	}

	stored.balance = stored.balance - sum
	stored.mutations = append(stored.mutations, -1*sum)
	b.accounts[key] = stored

	return stored.balance, blindSignatures, nil
}

func (b *Bank) WithdrawFullUnblinded(ctx context.Context, _ []byte, account banking.AccountToken) (*anonpay.UnblindedCredit, error) {
	// update the balance in storage.
	b.mu.Lock()
	defer b.mu.Unlock()

	key := keyForAccount(account)
	stored, ok := b.accounts[key]
	if !ok || stored.balance <= 0 {
		return nil, errors.New("account does not exist")
	}

	if stored.balance > currency.MaxAmount {
		return nil, errors.New("can't withdraw balance over max currency amount")
	}

	creditAmount, err := b.roundFunc(uint64(stored.balance))
	if err != nil {
		return nil, err
	}

	credit, err := b.issuer.IssueUnblindedCredit(ctx, creditAmount)
	if err != nil {
		return nil, fmt.Errorf("could not create credit: %w", err)
	}

	roundingMutation := stored.balance - creditAmount.AmountOrZero()
	stored.balance = 0
	stored.mutations = append(stored.mutations, -1*creditAmount.AmountOrZero())
	b.accounts[key] = stored
	b.roundingMutations = append(b.roundingMutations, roundingMutation)

	return credit, nil
}

func (b *Bank) Deposit(ctx context.Context, _ []byte, account banking.AccountToken, credit *anonpay.BlindedCredit) (balance int64, err error) {
	amount, err := credit.Value().Amount()
	if err != nil {
		return 0, anonpay.InputError{
			Err: fmt.Errorf("can't deposit special credit: %w", err),
		}
	}

	if amount <= 0 {
		return 0, anonpay.InputError{
			Err: errors.New("can't deposit zero amount"),
		}
	}

	tx, err := b.processor.BeginTransaction(ctx, credit)
	if err != nil {
		return 0, fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer func() {
		err = errors.Join(err, tx.Rollback())
	}()

	err = tx.Commit()
	if err != nil {
		return 0, err
	}

	b.mu.Lock()
	defer b.mu.Unlock()
	key := keyForAccount(account)
	stored := b.accounts[key]
	stored.balance += amount
	stored.mutations = append(stored.mutations, credit.Value().AmountOrZero())
	b.accounts[key] = stored

	return stored.balance, nil
}

func (b *Bank) Exchange(ctx context.Context, _ []byte, credit anonpay.AnyCredit, request anonpay.BlindSignRequest) (blindSignature []byte, err error) {
	amount, err := request.Value.Amount()
	if err != nil {
		return nil, anonpay.InputError{
			Err: fmt.Errorf("can't exchange special credit: %w", err),
		}
	}

	if amount <= 0 {
		return nil, anonpay.InputError{
			Err: errors.New("can't exchange credit with zero amount"),
		}
	}

	return b.exchanger.Exchange(ctx, credit, request)
}

func (b *Bank) Balance(ctx context.Context, account banking.AccountToken) (balance int64, err error) {
	b.mu.RLock()
	defer b.mu.RUnlock()

	key := keyForAccount(account)
	stored := b.accounts[key]
	return stored.balance, nil
}

// AccountHistory returns the account mutations.
//
// Not part of the [banking.BlindBankContract], but useful
// when using the in memory bank in tests.
func (b *Bank) AccountHistory(account banking.AccountToken) []int64 {
	b.mu.RLock()
	defer b.mu.RUnlock()

	key := keyForAccount(account)
	stored := b.accounts[key]
	return slices.Clone(stored.mutations)
}

// TotalBalance returns the balance across all accounts.
//
// Not part of the [banking.BlindBankContract], but useful
// when using the in memory bank in tests.
func (b *Bank) TotalBalance() int64 {
	b.mu.RLock()
	defer b.mu.RUnlock()

	sum := int64(0)
	for _, acc := range b.accounts {
		sum += acc.balance
	}
	return sum
}

// RoundingMutations returns the parts of mutations that happened
// as a result of rounding. Rounding happens when a bank account is fully
// withdrawn, but the balance couldn't be represented as a currency value.
//
// Negative mutations are "withdrawn" from the bank (a result of rounding a balance up).
// Positive values are "deposited" into the bank (a result of rounding a balance down).
//
// Not part of the [banking.BlindBankContract], but useful
// when using the in memory bank in tests.
func (b *Bank) RoundingMutations() []int64 {
	b.mu.RLock()
	defer b.mu.RUnlock()

	return slices.Clone(b.roundingMutations)
}

type storedAccount struct {
	balance   int64
	mutations []int64
}

func keyForAccount(account banking.AccountToken) string {
	key := keyHash.Sum(account.SecretBytes())
	return hex.EncodeToString(key)
}
