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

	"github.com/openpcc/openpcc/anonpay/currency"
	"github.com/openpcc/openpcc/anonpay/wallet/internal/stats"
	"github.com/openpcc/openpcc/anonpay/wallet/internal/transfer"
	"github.com/openpcc/openpcc/work"
)

type ProvideAccountStats struct {
	SourceTransfers *stats.TransferCounter
}

func NewProvideAccountStats() *ProvideAccountStats {
	return &ProvideAccountStats{
		SourceTransfers: stats.NewTransferCounter(),
	}
}

type ProvideAccountsSteps struct {
	ID                           string
	Stats                        *ProvideAccountStats
	WorkPool                     *work.Pool
	SourceAmount                 currency.Value
	MaxParallelSourceAccounts    int
	SourceFunc                   func(ctx context.Context) (*transfer.Source, error)
	EmptyBankAccountFunc         func(ctx context.Context) (*transfer.Account, error)
	InputDoneSignal              <-chan struct{}
	InputAccounts                <-chan *transfer.Account
	OutputFullAccountsToWithdraw *work.Channel[*transfer.Account]
	OutputAccountsToSource       *work.Channel[*transfer.Account]
}

func NewProvideAccountsSteps(s *ProvideAccountsSteps) []work.PipelineStep {
	// verify dev provided inputs to aid with debugging.
	work.MustHaveInput(s.ID, s.InputDoneSignal)
	work.MustHaveInput(s.ID, s.InputAccounts)
	work.MustHaveOutput[*transfer.Account](s.ID, s.OutputFullAccountsToWithdraw)
	work.MustHaveOutput[*transfer.Account](s.ID, s.OutputAccountsToSource)

	steps := pipelineSteps{}

	emptyAccounts := work.NewChannel[*transfer.Account](s.ID+".EmptyAccounts", 0)
	steps.add(work.PipelineStep{
		ID:      s.ID + ".ProduceEmptyAccountsUntilClose",
		Outputs: work.StepOutputs(emptyAccounts),
		FuncWithError: func(ctx context.Context) error {
			for {
				select {
				case _, ok := <-s.InputDoneSignal:
					if !ok {
						return nil
					}
				default:
				}

				acc, err := s.EmptyBankAccountFunc(ctx)
				if err != nil {
					return err
				}

				select {
				case _, ok := <-s.InputDoneSignal:
					if !ok {
						return nil
					}
				case emptyAccounts.SendCh <- acc:
				}
			}
		},
	})

	fullAccountsFromSource := work.NewChannel[*transfer.Account](s.ID+".FullAccountsFromSource", 0)
	steps.add(NewCombinedTransferSteps(&CombinedTransferSteps[*transfer.Source, *transfer.Account]{
		WorkPool:          s.WorkPool,
		ID:                s.ID + ".SourceTransfers",
		InputDepositables: emptyAccounts.ReceiveCh,
		Logger:            &transfer.NoopLogger[*transfer.Source, *transfer.Account]{},
		StatsFunc: func(tsfr *transfer.Transfer[*transfer.Source, *transfer.Account]) {
			s.Stats.SourceTransfers.Count(tsfr.RoundingGain(), tsfr.Amounts()...)
		},
		NewIntent: func(ctx context.Context, _ *transfer.Source, acc *transfer.Account) (*transfer.Intent[*transfer.Source, *transfer.Account], error) {
			src, err := s.SourceFunc(ctx)
			if err != nil {
				return nil, fmt.Errorf("failed to get source reference: %w", err)
			}
			return &transfer.Intent[*transfer.Source, *transfer.Account]{
				Withdrawal: transfer.Withdrawal{
					Credits: 1,
					Amount:  s.SourceAmount,
					// We don't know how much balance the source has available,
					// so make this an optimistic transfer.
					Optimistic: true,
				},
				From: src,
				To:   acc,
			}, nil
		},
		MaxParallel:        s.MaxParallelSourceAccounts,
		OutputDepositables: fullAccountsFromSource,
	})...)

	// withdrawableAccounts is NOT managed by the work package and will be closed manually
	// during the execution of the RouteAccounts step to facilitate early shutdown of EarlyExitFullAcountsToWithdraw.
	withdrawableAccounts := work.NewChannel[*transfer.Account](s.ID+".WithdrawableAccounts", 0)
	steps.add(work.PipelineStep{
		ID:      s.ID + ".RouteAccounts",
		Outputs: work.StepOutputs(s.OutputAccountsToSource), // Note: withdrawableAccounts is missing here on purpose, see comment above.
		Func: func() {
			// This step accepts three inputs and needs to exit when the closeSignal channel is closed.
			//
			// When the close signal is received, this step should immediately close withdrawableAccounts so that
			// the other pipeline sections can begin shutting down as well.
			//
			// After that it will still need to drain both from s.InputAccounts and fullAccountsFromSource by
			// sending them to s.OutputAccounts.
			//
			// closeSignal should be set to nil after it's closed.
			closeSignal := s.InputDoneSignal

			// We want to prioritize existing accounts over new accounts pulled from source. Both channels should
			// be set to nil after they are closed.
			inPriority := s.InputAccounts
			inFallback := fullAccountsFromSource.ReceiveCh

			for {
				var (
					acc *transfer.Account
					ok  bool
				)

				select {
				// receive either a close signal, or a priority account.
				case _, ok = <-closeSignal:
					if !ok {
						withdrawableAccounts.Close()
						closeSignal = nil
					}
				case acc, ok = <-inPriority:
					if !ok {
						inPriority = nil
					}
				default:
					// no priority account available, receive either a close signal or any account.
					select {
					case _, ok = <-closeSignal:
						if !ok {
							withdrawableAccounts.Close()
							closeSignal = nil
						}
					case acc, ok = <-inPriority:
						if !ok {
							inPriority = nil
						}
					case acc, ok = <-inFallback:
						if !ok {
							inFallback = nil
						}
					}
				}

				// all inputs closed, exit.
				if closeSignal == nil && inPriority == nil && inFallback == nil {
					return
				}

				// an input was closed, continue on to the next iteration.
				if !ok {
					continue
				}

				if closeSignal == nil || acc.Balance() < s.SourceAmount.AmountOrZero() {
					s.OutputAccountsToSource.SendCh <- acc
				} else {
					withdrawableAccounts.SendCh <- acc
				}
			}
		},
	})

	// without this step, s.OutputFullAccountsToWithdraw would remain open until
	// the .RouteAccounts step has exited due to the pipeline managed channel.
	//
	// This step allows us close it after withdrawableAccounts is closed instead.
	steps.add(work.PipelineStep{
		ID:      s.ID + ".EarlyExitFullAcountsToWithdraw",
		Outputs: work.StepOutputs(s.OutputFullAccountsToWithdraw),
		Func: func() {
			for {
				acc, ok := <-withdrawableAccounts.ReceiveCh
				if !ok {
					return
				}

				s.OutputFullAccountsToWithdraw.SendCh <- acc
			}
		},
	})

	return steps
}
