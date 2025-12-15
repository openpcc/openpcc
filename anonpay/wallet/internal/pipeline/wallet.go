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

package pipeline

import (
	"context"
	"time"

	"github.com/openpcc/openpcc/anonpay/currency"
	"github.com/openpcc/openpcc/anonpay/wallet/internal/stats"
	"github.com/openpcc/openpcc/anonpay/wallet/internal/transfer"
	"github.com/openpcc/openpcc/work"
)

type SourceFunc func(ctx context.Context) (*transfer.Source, error)
type AccountFunc func(ctx context.Context) (*transfer.Account, error)
type BankBatchFunc func(ctx context.Context) (*transfer.BankBatch, error)

// WalletStats holds the live statistics of the pipeline. It contains
// active counters of different sections of the pipeline.
//
// Note that this is different from [Status], which contains a
// moment-in-time reading of WalletStats.
type WalletStats struct {
	ProvideAccount   *ProvideAccountStats
	PrefetchWithdraw *PrefetchWithdrawStats
	Consolidate      *ConsolidateStats
	ReturnToSource   *ReturnToSourceStats
	// PaymentResults currently needs to be counted by the caller when enqueuing a payment result.
	PaymentResults *stats.TransferCounter
}

func NewWalletStats() *WalletStats {
	return &WalletStats{
		ProvideAccount:   NewProvideAccountStats(),
		PrefetchWithdraw: NewPrefetchWithdrawStats(),
		Consolidate:      NewConsolidateStats(),
		ReturnToSource:   NewReturnToSourceStats(),
		PaymentResults:   stats.NewTransferCounter(),
	}
}

type Status struct {
	BankBatchCreditCount stats.CreditCount
	SpendCreditCount     stats.CreditCount
	AmountInAccounts     int64
}

func (s *WalletStats) CalcWalletStatus() Status {
	sourceToAccounts := s.ProvideAccount.SourceTransfers.Read()
	accountsToSource := s.ReturnToSource.FromAccounts.Read()
	batchesToSource := s.ReturnToSource.FromBankBatches.Read()

	accountsToBatches := s.PrefetchWithdraw.SplitAccounts.Read()
	batchesToConsolidate := s.Consolidate.FromBankBatches.Read()
	accountsToConsolidate := s.Consolidate.FromAccounts.Read()
	paymentResultsToConsolidate := s.Consolidate.FromPaymentResults.Read()
	batchesToPaymentReqs := s.PrefetchWithdraw.PaymentRequests.Read()
	paymentResults := s.PaymentResults.Read()

	consolidatablesToAccounts := stats.SumTransferCounts(
		batchesToConsolidate,
		accountsToConsolidate,
		paymentResultsToConsolidate,
	)

	allAccounts := stats.SumTransferCounts(sourceToAccounts, consolidatablesToAccounts)

	return Status{
		BankBatchCreditCount: stats.CreditCountBetween(accountsToBatches, batchesToPaymentReqs, batchesToSource, batchesToConsolidate),
		SpendCreditCount:     stats.CreditCountBetween(batchesToPaymentReqs, paymentResults),
		AmountInAccounts:     stats.CreditCountBetween(allAccounts, accountsToBatches, accountsToConsolidate, accountsToSource).Amount,
	}
}

// WalletSteps models the full pipeline of transfers.
//
// The wallet pipeline is divided into 6 sections connected by channels.
//
// TODO: AdhocWithdraw is not implemented yet.
//
//	InputPrefetchPaymentRequests──────────────────────────────────────┐
//	InputAdhocPaymentRequests────────────────────────────────────────┐│
//	InputSignal──────────┐                                           ││
//	InputPaymentResults─┐│                                           ││             ┌─────────────┐
//	                    ││                                          ┌▼┴─────────────┴┐            │
//	                    ││                                         ┌►PrefetchWithdraw├─────────┐  │
//	                    ││┌───────────────┐                        │└─┬──────────────┘         │  │
//	                    │└►ProvideAccounts├─FullAccountsToWithdraw─┤  │                        │  │
//	                    │ └▲─────────────┬┘                        │┌─▼───────────┐            │  │
//	                    │  │             │                         └►AdhocWithdraw├────────────┤  │
//	                    │  │         AccountsToSource─┐             └─────────────┘            │  │
//	                    │  │                         ┌▼─────────────┐                          │  │
//	                    │  │                         │ReturnToSource│                          │  │
//	                    │  └──AccountsToProvide──┐   └──────────────┘  ┌─AccountsToConsolidate─┘  │
//	                    │ ┌──────────────────┐   │  ┌──────────────────▼┐                         │
//	                    └─►ConsolidateResults├───┴──┤ConsolidateAccounts◄─BankBatchesToConsoldate─┘
//	                      └──────────────────┘      └───────────────────┘
type WalletSteps struct {
	ID       string
	Stats    *WalletStats
	WorkPool *work.Pool

	SourceAmount              currency.Value
	PrefetchAmount            currency.Value
	MaxParallelSourceAccounts int
	MaxParallelBankBatches    int
	MaxParallelPaymentResults int
	AccountFunc               AccountFunc
	SourceFunc                SourceFunc
	BankBatchFunc             BankBatchFunc

	// Closing the InputSignal will trigger a shutdown of the wallet pipeline.
	InputSignal                  <-chan struct{}
	InputPrefetchPaymentRequests <-chan *transfer.PaymentRequest
	// InputAdhocPaymentRequests    <-chan *transfer.PaymentRequest
	InputPaymentResults <-chan *transfer.PaymentResult
}

func NewWalletSteps(s *WalletSteps) []work.PipelineStep {
	// verify dev provided inputs to aid with debugging.
	work.MustHaveInput(s.ID, s.InputSignal)
	work.MustHaveInput(s.ID, s.InputPrefetchPaymentRequests)
	// work.MustHaveInput(s.ID, s.InputAdhocPaymentRequests)
	work.MustHaveInput(s.ID, s.InputPaymentResults)

	accountsToProvide := work.NewChannel[*transfer.Account](s.ID+".AccountsToProvide", 0)
	fullAccountsToWithdraw := work.NewChannel[*transfer.Account](s.ID+".FullAccountsToWithdraw", 0)
	accountsToConsolidate := work.NewChannel[*transfer.Account](s.ID+".AccountsToConsolidate", 0)
	accountsToSource := work.NewChannel[*transfer.Account](s.ID+".AccountsToSource", 0)
	bankBatchesToConsolidate := work.NewChannel[*transfer.BankBatch](s.ID+".BankBatchesToConsolidate", 0)

	steps := pipelineSteps{}
	steps.add(NewProvideAccountsSteps(&ProvideAccountsSteps{
		ID:                           s.ID + ".ProvideAccounts",
		Stats:                        s.Stats.ProvideAccount,
		WorkPool:                     s.WorkPool,
		SourceFunc:                   s.SourceFunc,
		SourceAmount:                 s.SourceAmount,
		MaxParallelSourceAccounts:    s.MaxParallelSourceAccounts,
		EmptyBankAccountFunc:         s.AccountFunc,
		InputDoneSignal:              s.InputSignal,
		InputAccounts:                accountsToProvide.ReceiveCh,
		OutputFullAccountsToWithdraw: fullAccountsToWithdraw,
		OutputAccountsToSource:       accountsToSource,
	})...)

	steps.add(NewPrefetchWithdrawSteps(&PrefetchWithdrawSteps{
		ID:                             s.ID + ".PrefetchWithdraw",
		Stats:                          s.Stats.PrefetchWithdraw,
		WorkPool:                       s.WorkPool,
		BankBatchFunc:                  s.BankBatchFunc,
		PrefetchAmount:                 s.PrefetchAmount,
		MaxParallelBankBatches:         s.MaxParallelBankBatches,
		MaxExpiryDuration:              time.Hour * 8,
		InputRequests:                  s.InputPrefetchPaymentRequests,
		InputAccounts:                  fullAccountsToWithdraw.ReceiveCh,
		OutputBankBatchesToConsolidate: bankBatchesToConsolidate,
		OutputAccountsToConsolidate:    accountsToConsolidate,
	})...)

	steps.add(NewConsolidateSteps(&ConsolidateSteps{
		ID:                              s.ID + ".ConsolidateResults",
		Stats:                           s.Stats.Consolidate,
		WorkPool:                        s.WorkPool,
		MaxParallelConsolidatedAccounts: s.MaxParallelPaymentResults,
		AccountFunc:                     s.AccountFunc,
		TargetBalance:                   s.SourceAmount.AmountOrZero(),
		InputPaymentResults:             s.InputPaymentResults,
		Output:                          accountsToProvide,
	})...)

	steps.add(NewConsolidateSteps(&ConsolidateSteps{
		ID:                              s.ID + ".ConsolidateAccounts",
		Stats:                           s.Stats.Consolidate,
		WorkPool:                        s.WorkPool,
		MaxParallelConsolidatedAccounts: s.MaxParallelSourceAccounts,
		AccountFunc:                     s.AccountFunc,
		TargetBalance:                   s.SourceAmount.AmountOrZero(),
		InputAccounts:                   accountsToConsolidate.ReceiveCh,
		InputBankBatches:                bankBatchesToConsolidate.ReceiveCh,
		Output:                          accountsToProvide,
	})...)

	steps.add(NewReturnToSourceSteps(&ReturnToSourceSteps{
		ID:         s.ID + ".ReturnToSource",
		Stats:      s.Stats.ReturnToSource,
		WorkPool:   s.WorkPool,
		SourceFunc: s.SourceFunc,
		// TODO: See if this is enough, we could likely be returning more when doing a shutdown.
		MaxParallelTransfers: (s.MaxParallelSourceAccounts + s.MaxParallelBankBatches + s.MaxParallelPaymentResults),
		InputBankBatches:     bankBatchesToConsolidate.ReceiveCh,
		InputAccounts:        accountsToSource.ReceiveCh,
	})...)

	return steps
}
