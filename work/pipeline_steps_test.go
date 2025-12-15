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

package work_test

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"

	"github.com/openpcc/openpcc/work"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParallelStep(t *testing.T) {
	tests := map[string]struct {
		valsFunc    func() []int
		maxParallel int
		workers     int
		wantInOrder bool
	}{
		"ok, sequential due to max parallel 1": {
			valsFunc: func() []int {
				out := []int{}
				for nr := range 1000 {
					out = append(out, nr)
				}
				return out
			},
			maxParallel: 1,
			wantInOrder: true,
			workers:     5,
		},
		"ok, sequential due to single worker": {
			valsFunc: func() []int {
				out := []int{}
				for nr := range 1000 {
					out = append(out, nr)
				}
				return out
			},
			maxParallel: 5,
			wantInOrder: true,
			workers:     1,
		},
		"ok, in parallel": {
			valsFunc: func() []int {
				out := []int{}
				for nr := range 1000 {
					out = append(out, nr)
				}
				return out
			},
			maxParallel: 5,
			workers:     5,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			wp := runWorkPool(t, 0, tc.workers)

			vals := tc.valsFunc()
			input := make(chan int)
			go func() {
				for _, val := range vals {
					input <- val
				}
				close(input)
			}()

			output := work.NewChannel[int]("output", 0)
			step := work.NewParallelStep(&work.ParallelStep[int, int]{
				ID:          "test",
				Pool:        wp,
				MaxParallel: tc.maxParallel,
				Func: func(ctx context.Context, in int) (int, error) {
					return in, nil
				},
				Input:  input,
				Output: output,
			})

			runSteps(t, step)

			var got []int
			for val := range output.ReceiveCh {
				got = append(got, val)
			}

			if tc.wantInOrder {
				require.Equal(t, vals, got)
			} else {
				require.ElementsMatch(t, vals, got)
			}
		})
	}

	t.Run("fail, context cancelled receiving input", func(t *testing.T) {
		wp := runWorkPool(t, 0, 1)

		output := work.NewChannel[int]("output", 0)
		input := make(chan int)
		step := work.NewParallelStep(&work.ParallelStep[int, int]{
			ID:          "test",
			Pool:        wp,
			MaxParallel: 1,
			Func: func(ctx context.Context, in int) (int, error) {
				return in, nil
			},
			Input:  input,
			Output: output,
		})

		ctx, cancel := context.WithCancel(t.Context())
		done := make(chan error)
		go func() {
			cleanup, err := step.FuncWithCleanup(ctx)
			done <- err
			cleanup()
			done <- nil
		}()
		cancel()
		err := <-done
		require.ErrorIs(t, err, context.Canceled)
		close(input)
		err = <-done
		require.NoError(t, err)
	})

	t.Run("fail, context cancellation reaches func", func(t *testing.T) {
		const inputs = 500
		wp := runWorkPool(t, 0, 5)

		ctx, cancel := context.WithCancel(t.Context())
		input := make(chan int)
		go func() {
			for val := range inputs {
				if val == inputs/2 {
					cancel()
				}
				input <- val + 1
			}
			close(input)
		}()

		seenSum := &atomic.Int64{}
		output := work.NewChannel[int]("output", 0)
		step := work.NewParallelStep(&work.ParallelStep[int, int]{
			ID:          "test",
			Pool:        wp,
			MaxParallel: 1,
			Func: func(ctx context.Context, in int) (int, error) {
				select {
				case <-ctx.Done():
					return 0, ctx.Err()
				default:
					return in, nil
				}
			},
			Input:  input,
			Output: output,
			DrainInputFunc: func(in int, _ error) {
				seenSum.Add(int64(in))
			},
		})

		done := make(chan error)
		go func() {
			cleanup, err := step.FuncWithCleanup(ctx)
			cleanup()
			err = errors.Join(err, output.Close())
			done <- err
		}()

		for out := range output.ReceiveCh {
			seenSum.Add(int64(out))
		}

		err := <-done
		require.ErrorIs(t, err, context.Canceled)

		// because the context gets cancelled, we don't fully drain the input.
		for val := range input {
			seenSum.Add(int64(val))
		}

		inputsSum := int64(inputs * (inputs + 1) / 2)
		require.Equal(t, inputsSum, seenSum.Load())
	})

	t.Run("fail, exit when one parallel step fails", func(t *testing.T) {
		const inputs = 500
		wp := runWorkPool(t, 0, 5)

		input := make(chan int)
		go func() {
			for val := range inputs {
				input <- val + 1
			}
			close(input)
		}()

		seenSum := &atomic.Int64{}
		output := work.NewChannel[int]("output", 5)
		step := work.NewParallelStep(&work.ParallelStep[int, int]{
			ID:          "test",
			Pool:        wp,
			MaxParallel: 5,
			Func: func(ctx context.Context, in int) (int, error) {
				if in == inputs/2 {
					return in, assert.AnError
				}
				return in, nil
			},
			Input:  input,
			Output: output,
			DrainInputFunc: func(in int, _ error) {
				seenSum.Add(int64(in))
			},
		})

		done := make(chan error)
		go func() {
			cleanup, err := step.FuncWithCleanup(t.Context())
			cleanup()
			err = errors.Join(err, output.Close())
			done <- err
		}()

		for out := range output.ReceiveCh {
			seenSum.Add(int64(out))
		}

		err := <-done
		require.ErrorIs(t, err, assert.AnError)

		inputsSum := int64(inputs * (inputs + 1) / 2)
		require.Equal(t, inputsSum, seenSum.Load())
	})
}

//nolint:unparam
func runWorkPool(t *testing.T, maxOpenJobs, workers int) *work.Pool {
	wp := work.NewPool(maxOpenJobs, workers)
	t.Cleanup(func() {
		wp.Close()
	})

	return wp
}

func runSteps(t *testing.T, steps ...work.PipelineStep) {
	p, err := work.RunPipeline(t.Context(), steps...)
	require.NoError(t, err)
	t.Cleanup(func() {
		require.NoError(t, p.Close(t.Context()))
	})
}
