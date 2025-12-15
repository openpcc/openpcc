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
	"errors"
	"fmt"
	"sync"

	"github.com/openpcc/openpcc/anonpay/wallet/internal/transfer"
	"github.com/openpcc/openpcc/work"
)

// CombinedTransferSteps combines withdrawables and depositables into transfer intents, processes
// those transfers and outputs the resulting withdrawables and/or depositables.
type CombinedTransferSteps[W transfer.Withdrawable, D transfer.Depositable] struct {
	ID          string
	WorkPool    *work.Pool
	MaxParallel int
	Logger      transfer.IntentLogger[W, D]
	// StatsFunc is a callback that will be called when a transfer has completed. Can be used to keep track
	// of stats.
	StatsFunc func(intent *transfer.Transfer[W, D])
	// NewIntent is a required function that that determines how transfers are constructed.
	NewIntent func(ctx context.Context, from W, to D) (*transfer.Intent[W, D], error)
	// MapOutputFunc is an optional function that filters which withdrawables and depositables are output.
	MapOutputFunc func(t *transfer.Transfer[W, D]) (bool, bool)
	// InputWithdrawables is an optional input for withdrawables that should be used in transfers.
	InputWithdrawables <-chan W
	// InputDepositables is an optional input for depositables that should be used as the depositable side of a transfer.
	InputDepositables <-chan D
	// OutputWithdrawables is an optional output to which withdrawables that were part of a transfer are output.
	OutputWithdrawables *work.Channel[W]
	// OutputDepositables is an optional output to which depositables that were part of a transfer are output.
	OutputDepositables *work.Channel[D]
	// CombinedTransferSteps begins shutting down when one of the Input channels is closed, since
	// this doesn't guarantee that the other input channel is empty, it might need to be drained.
	DrainWithdrawables *work.Channel[W]
	DrainDepositables  *work.Channel[D]
}

func NewCombinedTransferSteps[W transfer.Withdrawable, D transfer.Depositable](s *CombinedTransferSteps[W, D]) []work.PipelineStep {
	steps := pipelineSteps{}
	// Both inputs are optional, can hardcode transfer inputs in NewIntent.
	intents := work.NewChannel[*transfer.Intent[W, D]](s.ID+".Intents", 0)
	steps.add(work.PipelineStep{
		ID:      s.ID + ".CreateIntents",
		Outputs: work.StepOutputs(intents, s.DrainWithdrawables, s.DrainDepositables),
		// Using FuncWithCleanup because this step can return early due to s.NewIntent
		// errors. It might require cleanup to drain the input channel.
		FuncWithCleanup: func(ctx context.Context) (work.CleanupFunc, error) {
			inFrom := s.InputWithdrawables
			inTo := s.InputDepositables
			var unhandledFrom *W

			cleanup := func() {
				wg := &sync.WaitGroup{}
				wg.Go(func() {
					if unhandledFrom != nil && s.DrainWithdrawables != nil {
						s.DrainWithdrawables.SendCh <- *unhandledFrom
					}
					work.DrainInput(inFrom, func(from W) {
						if s.DrainWithdrawables != nil {
							s.DrainWithdrawables.SendCh <- from
						}
					})
				})

				wg.Go(func() {
					work.DrainInput(inTo, func(to D) {
						if s.DrainDepositables != nil {
							s.DrainDepositables.SendCh <- to
						}
					})
				})

				wg.Wait()
			}

			for {
				var (
					from W
					to   D
					err  error
				)
				unhandledFrom = nil
				if inFrom != nil {
					// also exit when the context is cancelled, no need to wait for the intent to reach the transfer step.
					from, err = work.ReceiveInput(ctx, inFrom)
					if err != nil {
						if errors.Is(err, work.ErrInputClosed) {
							inFrom = nil
							break
						}
						return cleanup, err
					}
					unhandledFrom = &from
				}

				if inTo != nil {
					to, err = work.ReceiveInput(ctx, inTo)
					if err != nil {
						if errors.Is(err, work.ErrInputClosed) {
							inTo = nil
							break
						}
						return cleanup, err
					}
				}

				intent, err := s.NewIntent(ctx, from, to)
				if err != nil {
					return cleanup, fmt.Errorf("failed to create transfer input: %w", err)
				}
				intents.SendCh <- intent
			}
			return cleanup, nil
		},
	})

	// transfers channel is only set when there are output channels.
	var transfers *work.Channel[*transfer.Transfer[W, D]]
	if s.OutputDepositables != nil || s.OutputWithdrawables != nil {
		transfers = work.NewChannel[*transfer.Transfer[W, D]](s.ID+".Transfers", 0)
	}
	steps.add(NewTransferSteps(&TransferSteps[W, D]{
		ID:          s.ID + ".Transfer",
		WorkPool:    s.WorkPool,
		MaxParallel: s.MaxParallel,
		Logger:      s.Logger,
		StatsFunc:   s.StatsFunc,
		Input:       intents.ReceiveCh,
		Output:      transfers,
	})...)

	if s.OutputDepositables != nil || s.OutputWithdrawables != nil {
		steps.add(NewMapTransferStep(&MapTransferStep[W, D]{
			ID:                  s.ID + ".MapTransfersToOutputs",
			Input:               transfers.ReceiveCh,
			MapFunc:             s.MapOutputFunc,
			OutputWithdrawables: s.OutputWithdrawables,
			OutputDepositables:  s.OutputDepositables,
		}))
	}

	return steps
}

type TransferSteps[W transfer.Withdrawable, D transfer.Depositable] struct {
	ID          string
	WorkPool    *work.Pool
	Logger      transfer.IntentLogger[W, D]
	StatsFunc   func(intent *transfer.Transfer[W, D])
	MaxParallel int
	Input       <-chan *transfer.Intent[W, D]
	Output      *work.Channel[*transfer.Transfer[W, D]]
}

func NewTransferSteps[W transfer.Withdrawable, D transfer.Depositable](s *TransferSteps[W, D]) []work.PipelineStep {
	work.MustHaveInput(s.ID, s.Input)
	// output is optional.

	steps := pipelineSteps{}

	results := work.NewChannel[*transfer.Transfer[W, D]](s.ID+".Results", 0)
	steps.add(work.NewParallelStep(&work.ParallelStep[*transfer.Intent[W, D], *transfer.Transfer[W, D]]{
		Pool:        s.WorkPool,
		ID:          s.ID + ".ParallelTransfers",
		MaxParallel: s.MaxParallel,
		Func: func(ctx context.Context, intent *transfer.Intent[W, D]) (*transfer.Transfer[W, D], error) {
			tsfr, err := transfer.Process(ctx, intent, s.Logger)
			if err != nil {
				if intent.IsExpectedError(err) {
					// nils transfers will get filtered out in the next step.

					// nolint:nilnil
					return nil, nil
				}
				return nil, err
			}
			if s.StatsFunc != nil {
				s.StatsFunc(tsfr)
			}
			return tsfr, nil
		},
		Input:  s.Input,
		Output: results,
		DrainInputFunc: func(in *transfer.Intent[W, D], jobErr error) {
			// TODO: Either the transfer for this intent failed, or a
			// transfer was never attempted due to an earlier failure.
		},
	}))

	steps.add(work.PipelineStep{
		ID:      s.ID + ".FilterNilTransfers",
		Outputs: work.StepOutputs(s.Output),
		Func: func() {
			for {
				tsfr, ok := <-results.ReceiveCh
				if !ok {
					return
				}

				if tsfr == nil || s.Output == nil {
					continue
				}

				s.Output.SendCh <- tsfr
			}
		},
	})

	return steps
}

// MapTransferStep maps incoming transfers to just the withdrawables, depositables or both.
//
// Useful because other steps usually don't accept transfers as input, but do accept withdrawables
// and/or depositables.
type MapTransferStep[W transfer.Withdrawable, D transfer.Depositable] struct {
	ID                  string
	Input               <-chan *transfer.Transfer[W, D]
	MapFunc             func(*transfer.Transfer[W, D]) (bool, bool)
	OutputWithdrawables *work.Channel[W]
	OutputDepositables  *work.Channel[D]
}

func NewMapTransferStep[W transfer.Withdrawable, D transfer.Depositable](s *MapTransferStep[W, D]) work.PipelineStep {
	work.MustHaveInput(s.ID, s.Input)
	if s.OutputWithdrawables == nil && s.OutputDepositables == nil {
		panic(fmt.Sprintf("dev error: %s step requires at least one output to be set, both are nil", s.ID))
	}

	return work.PipelineStep{
		ID:      s.ID,
		Outputs: work.StepOutputs(s.OutputWithdrawables, s.OutputDepositables),
		Func: func() {
			for {
				tsfr, ok := <-s.Input
				if !ok {
					break
				}

				from, to := true, true
				if s.MapFunc != nil {
					from, to = s.MapFunc(tsfr)
				}

				if from && s.OutputWithdrawables != nil {
					s.OutputWithdrawables.SendCh <- tsfr.From()
				}

				if to && s.OutputDepositables != nil {
					s.OutputDepositables.SendCh <- tsfr.To()
				}
			}
		},
	}
}
