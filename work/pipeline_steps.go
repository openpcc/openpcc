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

package work

import (
	"context"
	"errors"
	"fmt"
	"sync"
)

// ParallelStep receives inputs, runs functions in parallel and sends outputs.
//
// There is no guarantee to the order of outputs.
type ParallelStep[In, Out any] struct {
	ID          string
	Pool        *Pool
	MaxParallel int
	Func        func(ctx context.Context, val In) (Out, error)
	Input       <-chan In
	Output      *Channel[Out]
	// DrainInputFunc is called for inputs for which no jobs were ever executed,
	// or for which the executed job failed, in which case the error is non-nil.
	DrainInputFunc func(in In, jobErr error)
}

func NewParallelStep[In, Out any](s *ParallelStep[In, Out]) PipelineStep {
	MustHaveInput(s.ID, s.Input)

	// shared between funcs
	input := s.Input

	return PipelineStep{
		ID:      s.ID,
		Outputs: StepOutputs(s.Output),
		FuncWithCleanup: func(stepCtx context.Context) (CleanupFunc, error) {
			type result struct {
				jobID       int64
				remainingIn *In
				output      *Out
				err         error
			}

			// manages a local buffer of results so that workers don't get
			// blocked writing results.
			results := make(chan result, max(0, s.MaxParallel-1))
			slots := make(chan struct{}, max(1, s.MaxParallel))
			ctx, cancelJobs := context.WithCancelCause(stepCtx)
			go func() {
				wg := &sync.WaitGroup{}
				defer func() {
					// wait for open jobs to be done.
					wg.Wait()
					close(results)
				}()
				for i := int64(0); ; i++ {
					// enqueue a slot to claim a job.
					select {
					case slots <- struct{}{}:
					case <-ctx.Done():
						results <- result{jobID: i, err: context.Cause(ctx)}
						return
					}

					// receive an input.
					in, err := ReceiveInput(ctx, s.Input)
					if err != nil {
						results <- result{jobID: i, err: err}
						return
					}

					// add the job to the pool.
					wg.Add(1)
					err = s.Pool.AddJob(ctx, JobFunc(func() {
						defer wg.Done()
						val, err := s.Func(ctx, in)
						if err != nil {
							cancelJobs(err)
							results <- result{jobID: i, remainingIn: &in, err: fmt.Errorf("func failed: %w", err)}
							return
						}
						results <- result{jobID: i, output: &val, err: err}
					}))
					if err != nil {
						wg.Done()
						results <- result{jobID: i, remainingIn: &in, err: fmt.Errorf("failed to add job to pool: %w", err)}
						return
					}
				}
			}()

			// collect job results and copy them to the output.
			var err error
			for result := range results {
				if result.err != nil {
					if errors.Is(result.err, ErrInputClosed) {
						result.err = nil
						input = nil
					} else {
						result.err = fmt.Errorf("job %d failed: %w", result.jobID, result.err)
					}
				}

				if s.DrainInputFunc != nil && result.remainingIn != nil {
					s.DrainInputFunc(*result.remainingIn, result.err)
				}

				if result.err != nil {
					// irrecoverable error, continue processing remaining results and then
					// return with error to iniatie pipeline shutdown.
					err = errors.Join(err, result.err)
					select {
					case <-slots:
					default:
					}
					continue
				}

				if result.output != nil && s.Output != nil {
					s.Output.SendCh <- *result.output
				}

				// open up a new slot if possible.
				select {
				case <-slots:
				default:
				}
			}

			return CleanupFunc(func() {
				// Invoked after cancellation signals have been send,
				DrainInput(input, func(in In) {
					if s.DrainInputFunc != nil {
						s.DrainInputFunc(in, nil)
					}
				})
			}), err
		},
	}
}
