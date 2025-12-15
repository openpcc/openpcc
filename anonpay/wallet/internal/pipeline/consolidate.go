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
	"fmt"
	"log/slog"

	"github.com/openpcc/openpcc/anonpay/wallet/internal/stats"
	"github.com/openpcc/openpcc/anonpay/wallet/internal/transfer"
	"github.com/openpcc/openpcc/work"
)

type ConsolidateStats struct {
	FromAccounts       *stats.TransferCounter
	FromBankBatches    *stats.TransferCounter
	FromPaymentResults *stats.TransferCounter
}

func NewConsolidateStats() *ConsolidateStats {
	return &ConsolidateStats{
		FromAccounts:       stats.NewTransferCounter(),
		FromBankBatches:    stats.NewTransferCounter(),
		FromPaymentResults: stats.NewTransferCounter(),
	}
}

// ConsolidateSteps consolidates accounts with low balance, bank batches and payment results
// into new accounts with a target amount.
type ConsolidateSteps struct {
	ID                              string
	Stats                           *ConsolidateStats
	WorkPool                        *work.Pool
	MaxParallelConsolidatedAccounts int
	AccountFunc                     AccountFunc
	// TargetBalance is the desired balance for output accounts,
	// the last consolidated account might have less.
	TargetBalance       int64
	InputBankBatches    <-chan *transfer.BankBatch
	InputPaymentResults <-chan *transfer.PaymentResult
	InputAccounts       <-chan *transfer.Account
	Output              *work.Channel[*transfer.Account]
}

type Consolidatable interface {
	transfer.Withdrawable
	Balance() int64
}

func NewConsolidateSteps(s *ConsolidateSteps) []work.PipelineStep {
	// verify dev provided inputs to aid with debugging.
	// needs at least one input
	if s.InputBankBatches == nil && s.InputPaymentResults == nil && s.InputAccounts == nil {
		panic("dev error: input" + s.ID + " requires at least one input, all nil")
	}

	work.MustHaveOutput[*transfer.Account](s.ID, s.Output)

	steps := pipelineSteps{}
	var lowAccounts *work.Channel[*transfer.Account]
	if s.InputAccounts != nil {
		// forward accounts with enough balance to the output, consolidate low balance accounts.
		lowAccounts = work.NewChannel[*transfer.Account](s.ID+".LowAccounts", 0)
		steps.add(work.PipelineStep{
			ID:      s.ID + ".FilterFullAccounts",
			Outputs: work.StepOutputs(lowAccounts),
			Func: func() {
				for {
					acc, ok := <-s.InputAccounts
					if !ok {
						break
					}

					if acc.Balance() < s.TargetBalance {
						lowAccounts.SendCh <- acc
					} else {
						s.Output.SendCh <- acc
					}
				}
			},
		})
	}

	// combine low accounts, input batches and payment results into a single channel.
	consolidatables := work.NewChannel[Consolidatable](s.ID+".Consolidatables", 0)
	steps.add(work.PipelineStep{
		ID:      s.ID + ".CombineConsolidatables",
		Outputs: work.StepOutputs(consolidatables),
		Func: func() {
			// local vars for input channels so we can nil them safely to signal they're done.
			// any of of these can be nil.
			inputBankBatches := s.InputBankBatches
			var inputAccounts <-chan *transfer.Account
			inputPayResults := s.InputPaymentResults
			if lowAccounts != nil {
				inputAccounts = lowAccounts.ReceiveCh
			}

			for {
				var (
					val Consolidatable
					ok  bool
				)
				select {
				case val, ok = <-inputBankBatches:
					if !ok {
						inputBankBatches = nil
					}
				case val, ok = <-inputAccounts:
					if !ok {
						inputAccounts = nil
					}
				case val, ok = <-inputPayResults:
					if !ok {
						inputPayResults = nil
					}
				}

				if inputBankBatches == nil && inputAccounts == nil && inputPayResults == nil {
					// all inputs closed, exit.
					return
				}

				if !ok {
					// we didn't receive a value, but some channels are still open.
					continue
				}

				consolidatables.SendCh <- val
			}
		},
	})

	intents := work.NewChannel[*transfer.Intent[Consolidatable, transfer.RepDepositable[*transfer.Account]]](s.ID+".Intents", 0)
	steps.add(work.PipelineStep{
		ID:      s.ID + ".CreateIntents",
		Outputs: work.StepOutputs(intents),
		// Using FuncWithCleanup because this step can return early due to AccountFunc
		// errors. It might require cleanup to drain the input channel.
		FuncWithCleanup: func(ctx context.Context) (work.CleanupFunc, error) {
			input := consolidatables.ReceiveCh
			cleanup := work.CleanupFunc(func() {
				work.DrainInput(input, nil)
			})

			acc, err := s.AccountFunc(ctx)
			if err != nil {
				return cleanup, fmt.Errorf("failed to create empty bank account: %w", err)
			}

			virtualBalance := int64(0)
			lastGroupIndex := 0
			for {
				// also exit when the context is cancelled, no need to wait for the intent to reach the transfer step.
				val, err := work.ReceiveInput(ctx, input)
				if err != nil {
					return cleanup, work.DropErrInputClosed(err)
				}

				virtualBalance += val.Balance()
				index := lastGroupIndex + 1
				lastDupe := virtualBalance >= max(1, s.TargetBalance)
				// output duplicates of the current account until the virtual balance exceeds the target balance.
				intent := &transfer.Intent[Consolidatable, transfer.RepDepositable[*transfer.Account]]{
					Withdrawal: transfer.FullWithdrawal,
					From:       val,
					To: transfer.RepDepositable[*transfer.Account]{
						D:     acc,
						Index: index,
						Last:  lastDupe,
					},
				}

				// intent to send the full batch to the account.
				intents.SendCh <- intent

				// check if this was the last duplicate.
				if lastDupe {
					acc, err = s.AccountFunc(ctx)
					if err != nil {
						return cleanup, fmt.Errorf("failed to create empty bank account: %w", err)
					}
					virtualBalance = 0
					lastGroupIndex = 0
				}
			}
		},
	})

	transfers := work.NewChannel[*transfer.Transfer[Consolidatable, transfer.RepDepositable[*transfer.Account]]](s.ID+".Transfers", 0)
	steps.add(NewTransferSteps(&TransferSteps[Consolidatable, transfer.RepDepositable[*transfer.Account]]{
		ID:          s.ID + ".ConsolidateTransfer",
		WorkPool:    s.WorkPool,
		MaxParallel: s.MaxParallelConsolidatedAccounts,
		Logger:      &transfer.NoopLogger[Consolidatable, transfer.RepDepositable[*transfer.Account]]{},
		StatsFunc: func(tsfr *transfer.Transfer[Consolidatable, transfer.RepDepositable[*transfer.Account]]) {
			switch w := tsfr.From().(type) {
			case *transfer.Account:
				s.Stats.FromAccounts.Count(tsfr.RoundingGain(), tsfr.Amounts()...)
			case *transfer.BankBatch:
				s.Stats.FromBankBatches.Count(tsfr.RoundingGain(), tsfr.Amounts()...)
			case *transfer.PaymentResult:
				s.Stats.FromPaymentResults.Count(tsfr.RoundingGain(), tsfr.Amounts()...)
			default:
				slog.Warn("unexpected withdrawable in stats func", "warning", fmt.Sprintf("%T: %v", w, w))
			}
		},
		Input:  intents.ReceiveCh,
		Output: transfers,
	})...)

	steps.add(work.PipelineStep{
		ID:      s.ID + ".DedupeAccounts",
		Outputs: work.StepOutputs(s.Output),
		Func: func() {
			// collect repeated resultsByAcc.
			resultsByAcc := map[*transfer.Account]*transfer.RepResults{}
			for {
				tsfr, ok := <-transfers.ReceiveCh
				if !ok {
					break
				}

				results, ok := resultsByAcc[tsfr.To().D]
				if !ok {
					results = &transfer.RepResults{}
					resultsByAcc[tsfr.To().D] = results
				}
				results.Add(tsfr.To())
				if !results.Complete() {
					continue
				}

				// results are complete. Delete them and send account to output.
				delete(resultsByAcc, tsfr.To().D)
				s.Output.SendCh <- tsfr.To().D
			}

			if len(resultsByAcc) > 0 {
				for to := range resultsByAcc {
					// not all accounts will receive their final result, as there's no guarantee
					// we're receiving enough inputs to fill up accounts.
					s.Output.SendCh <- to
				}
			}
		},
	})

	return steps
}
