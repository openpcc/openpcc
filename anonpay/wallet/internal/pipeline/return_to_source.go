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

type ReturnToSourceStats struct {
	FromAccounts    *stats.TransferCounter
	FromBankBatches *stats.TransferCounter
}

func NewReturnToSourceStats() *ReturnToSourceStats {
	return &ReturnToSourceStats{
		FromAccounts:    stats.NewTransferCounter(),
		FromBankBatches: stats.NewTransferCounter(),
	}
}

type ReturnToSourceSteps struct {
	ID                   string
	Stats                *ReturnToSourceStats
	WorkPool             *work.Pool
	SourceFunc           SourceFunc
	MaxParallelTransfers int
	InputBankBatches     <-chan *transfer.BankBatch
	InputAccounts        <-chan *transfer.Account
}

func NewReturnToSourceSteps(s *ReturnToSourceSteps) []work.PipelineStep {
	// verify dev provided inputs to aid with debugging.
	work.MustHaveInput(s.ID, s.InputBankBatches)
	work.MustHaveInput(s.ID, s.InputAccounts)

	steps := pipelineSteps{}

	// combine both into a single channel
	withdrawables := work.NewChannel[transfer.Withdrawable](s.ID+".Combined", 0)
	steps.add(work.PipelineStep{
		ID:      s.ID + ".CombineInputs",
		Outputs: work.StepOutputs(withdrawables),
		Func: func() {
			inBatches := s.InputBankBatches
			inAccounts := s.InputAccounts

			for {
				var (
					w  transfer.Withdrawable
					ok bool
				)
				select {
				case w, ok = <-inBatches:
					if !ok {
						inBatches = nil
					}
				case w, ok = <-inAccounts:
					if !ok {
						inAccounts = nil
					}
				}

				// all inputs closed, early exit.
				if inBatches == nil && inAccounts == nil {
					return
				}

				// one fo the inputs was closed, receive a value next iteration.
				if !ok {
					continue
				}

				withdrawables.SendCh <- w
			}
		},
	})

	steps.add(NewCombinedTransferSteps(&CombinedTransferSteps[transfer.Withdrawable, *transfer.Source]{
		ID:          s.ID + ".SourceTransfers",
		WorkPool:    s.WorkPool,
		MaxParallel: s.MaxParallelTransfers,
		Logger:      &transfer.NoopLogger[transfer.Withdrawable, *transfer.Source]{},
		StatsFunc: func(tsfr *transfer.Transfer[transfer.Withdrawable, *transfer.Source]) {
			switch w := tsfr.From().(type) {
			case *transfer.Account:
				s.Stats.FromAccounts.Count(tsfr.RoundingGain(), tsfr.Amounts()...)
			case *transfer.BankBatch:
				s.Stats.FromBankBatches.Count(tsfr.RoundingGain(), tsfr.Amounts()...)
			default:
				slog.Warn("unexpected withdrawable in stats func", "warning", fmt.Sprintf("%T: %v", w, w))
			}
		},
		NewIntent: func(ctx context.Context, from transfer.Withdrawable, _ *transfer.Source) (*transfer.Intent[transfer.Withdrawable, *transfer.Source], error) {
			src, err := s.SourceFunc(ctx)
			if err != nil {
				return nil, fmt.Errorf("failed to get source: %w", err)
			}
			return &transfer.Intent[transfer.Withdrawable, *transfer.Source]{
				Withdrawal: transfer.FullWithdrawal,
				From:       from,
				To:         src,
			}, nil
		},
		InputWithdrawables: withdrawables.ReceiveCh,
	})...)

	return steps
}
