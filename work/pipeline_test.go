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
	"io"
	"sync/atomic"
	"testing"
	"time"

	"github.com/openpcc/openpcc/work"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPipelineRun(t *testing.T) {
	t.Run("ok, empty", func(t *testing.T) {
		p, err := work.RunPipeline(t.Context())
		require.NoError(t, err)

		err = p.Close(t.Context())
		require.NoError(t, err)
	})

	t.Run("ok, single step exits immediately", func(t *testing.T) {
		calls := &atomic.Int64{}
		p, err := work.RunPipeline(t.Context(), work.PipelineStep{
			ID: "1",
			FuncWithError: func(_ context.Context) error {
				calls.Add(1)
				return nil
			},
		})
		require.NoError(t, err)

		err = p.Close(t.Context())
		require.NoError(t, err)

		// ensure step was only called once
		require.Equal(t, int64(1), calls.Load())
	})

	t.Run("ok, step defaults to not receiving cancellation signal", func(t *testing.T) {
		calls := &atomic.Int64{}
		p, err := work.RunPipeline(t.Context(), work.PipelineStep{
			ID: "1",
			FuncWithError: func(ctx context.Context) error {
				timer := time.NewTimer(10 * time.Millisecond)
				select {
				case <-ctx.Done():
					// don't add to calls on purpose, so we can check whether the
					// right path was taken.
				case <-timer.C:
					calls.Add(1)
				}
				return nil
			},
		})
		require.NoError(t, err)

		// should immediately close the context
		err = p.Close(t.Context())
		require.NoError(t, err)

		// ensure step was only called once
		require.Equal(t, int64(1), calls.Load())
	})

	t.Run("ok, step can opt-in to pipeline cancellations signals, step receives cause", func(t *testing.T) {
		calls := &atomic.Int64{}
		stepCause := make(chan error, 1) // buffer so we don't block in the step.
		p, err := work.RunPipeline(t.Context(), work.PipelineStep{
			ID: "1",
			FuncWithError: func(ctx context.Context) error {
				calls.Add(1)
				// wait for the context to be done.
				<-ctx.Done()
				stepCause <- context.Cause(ctx)
				return nil
			},
			ReceivePipelineCancellation: true,
		})
		require.NoError(t, err)

		err = p.Close(t.Context()) // should trigger the cancellation signal.
		require.NoError(t, err)

		err = <-stepCause
		require.ErrorIs(t, err, context.Canceled)
		require.ErrorIs(t, err, work.ErrPipelineClosed)

		// ensure step was only called once
		require.Equal(t, int64(1), calls.Load())
	})

	t.Run("ok, input pipeline context cancellation closes pipeline, step receives cause", func(t *testing.T) {
		calls := &atomic.Int64{}
		ctx, cancel := context.WithCancelCause(t.Context())

		stepCause := make(chan error)
		p, err := work.RunPipeline(ctx, work.PipelineStep{
			ID: "1",
			FuncWithError: func(ctx context.Context) error {
				calls.Add(1)
				// wait for the context to be done.
				<-ctx.Done()
				stepCause <- context.Cause(ctx)
				return context.Cause(ctx)
			},
			ReceivePipelineCancellation: true,
		})
		require.NoError(t, err)

		cancel(assert.AnError)
		require.ErrorIs(t, <-stepCause, assert.AnError)

		// verify that the error passed to the context is returned via close.
		err = p.Close(t.Context())
		require.Error(t, err)
		require.ErrorIs(t, err, assert.AnError)

		// ensure step was only called once
		require.Equal(t, int64(1), calls.Load())
	})

	t.Run("fail, cancellation of close ctx is received even by non-cancellation receiving steps", func(t *testing.T) {
		p, err := work.RunPipeline(t.Context(), work.PipelineStep{
			ID: "1",
			FuncWithError: func(ctx context.Context) error {
				<-ctx.Done()
				return context.Cause(ctx)
			},
		})
		require.NoError(t, err)

		// should immediately close the context
		ctx, cancel := context.WithCancelCause(t.Context())
		go func() {
			cancel(assert.AnError)
		}()
		err = p.Close(ctx)
		require.ErrorIs(t, err, assert.AnError)
	})

	t.Run("fail, step returns error, closes pipeline", func(t *testing.T) {
		calls := &atomic.Int64{}
		p, err := work.RunPipeline(t.Context(), work.PipelineStep{
			ID: "1",
			FuncWithError: func(_ context.Context) error {
				calls.Add(1)
				return assert.AnError
			},
			ReceivePipelineCancellation: true,
		})
		require.NoError(t, err)

		err = p.Close(t.Context())
		require.ErrorIs(t, err, assert.AnError)
		require.ErrorAs(t, err, &work.PipelineStepError{
			StepID: "1",
			Err:    assert.AnError,
		})

		// ensure step was only called once
		require.Equal(t, int64(1), calls.Load())
	})

	t.Run("fail, step returns error, other step receives cause", func(t *testing.T) {
		w1 := &atomic.Int64{}
		w2 := &atomic.Int64{}
		stepCause := make(chan error)
		p, err := work.RunPipeline(
			t.Context(),
			work.PipelineStep{
				ID:                          "1",
				ReceivePipelineCancellation: true,
				FuncWithError: func(ctx context.Context) error {
					w1.Add(1)
					// wait for the context to be done.
					<-ctx.Done()
					stepCause <- context.Cause(ctx)
					return nil
				},
			},
			work.PipelineStep{
				ID: "2",
				FuncWithError: func(ctx context.Context) error {
					w2.Add(1)
					return assert.AnError
				},
			},
		)
		require.NoError(t, err)

		// verify the error w1 got from the context.
		err = <-stepCause
		require.ErrorIs(t, err, assert.AnError)
		require.ErrorAs(t, err, &work.PipelineStepError{
			StepID: "2",
			Err:    assert.AnError,
		})

		err = p.Close(t.Context())
		require.ErrorIs(t, err, assert.AnError)
		require.ErrorAs(t, err, &work.PipelineStepError{
			StepID: "2",
			Err:    assert.AnError,
		})

		// ensure step were only called once
		require.Equal(t, int64(1), w1.Load())
		require.Equal(t, int64(1), w2.Load())
	})

	t.Run("ok, multiple steps, exit immediately", func(t *testing.T) {
		w1 := &atomic.Int64{}
		w2 := &atomic.Int64{}
		w3 := &atomic.Int64{}
		p, err := work.RunPipeline(
			t.Context(),
			work.PipelineStep{
				ID: "1",
				FuncWithError: func(_ context.Context) error {
					w1.Add(1)
					return nil
				},
			},
			work.PipelineStep{
				ID: "2",
				FuncWithError: func(_ context.Context) error {
					w2.Add(1)
					return nil
				},
			},
			work.PipelineStep{
				ID: "3",
				FuncWithError: func(_ context.Context) error {
					w3.Add(1)
					return nil
				},
			},
		)
		require.NoError(t, err)

		err = p.Close(t.Context())
		require.NoError(t, err)

		// ensure step were only called once
		require.Equal(t, int64(1), w1.Load())
		require.Equal(t, int64(1), w2.Load())
		require.Equal(t, int64(1), w3.Load())
	})

	t.Run("ok, typical multistep pipeline with producer", func(t *testing.T) {
		producerOut := make(chan int)
		doublerOut := make(chan int)

		got := &atomic.Int64{}
		p, err := work.RunPipeline(
			t.Context(),
			work.PipelineStep{
				ID: "producer",
				FuncWithError: func(_ context.Context) error {
					defer close(producerOut)
					for i := range 11 {
						producerOut <- i
					}
					return nil
				},
			},
			work.PipelineStep{
				ID: "doubler",
				FuncWithError: func(_ context.Context) error {
					defer close(doublerOut)
					for nr := range producerOut {
						doublerOut <- nr * 2
					}
					return nil
				},
			},
			work.PipelineStep{
				ID: "collector",
				FuncWithError: func(_ context.Context) error {
					for nr := range doublerOut {
						got.Add(int64(nr))
					}
					return nil
				},
			},
		)
		require.NoError(t, err)

		want := int64(55 * 2)
		require.EventuallyWithT(t, func(collectT *assert.CollectT) {
			assert.Equal(collectT, want, got.Load())
		}, 50*time.Millisecond, time.Millisecond)

		err = p.Close(t.Context())
		require.NoError(t, err)
	})

	t.Run("ok, step output gets closed", func(t *testing.T) {
		output := newTestCloser(nil)
		callsInStep := make(chan int64, 1) // buffered so we can load it after close.
		p, err := work.RunPipeline(t.Context(), work.PipelineStep{
			ID: "1",
			Outputs: map[string]io.Closer{
				"output": output,
			},
			FuncWithError: func(_ context.Context) error {
				callsInStep <- output.calls.Load()
				return nil
			},
		})
		require.NoError(t, err)

		err = p.Close(t.Context())
		require.NoError(t, err)

		require.Equal(t, int64(0), <-callsInStep)
		// ensure output was closed
		require.Equal(t, int64(1), output.calls.Load())
	})

	t.Run("ok, step output gets closed even if step returns error", func(t *testing.T) {
		output := newTestCloser(nil)
		callsInStep := make(chan int64, 1) // buffered so we can load it after close.
		p, err := work.RunPipeline(t.Context(), work.PipelineStep{
			ID: "1",
			Outputs: map[string]io.Closer{
				"output": output,
			},
			FuncWithError: func(_ context.Context) error {
				callsInStep <- output.calls.Load()
				return assert.AnError
			},
		})
		require.NoError(t, err)

		err = p.Close(t.Context())
		require.Error(t, err)

		require.Equal(t, int64(0), <-callsInStep)
		// ensure output was still closed
		require.Equal(t, int64(1), output.calls.Load())
	})

	t.Run("ok, output gets closed even if other steps are still running", func(t *testing.T) {
		output := newTestCloser(nil)
		p, err := work.RunPipeline(
			t.Context(),
			work.PipelineStep{
				ID:                          "1",
				ReceivePipelineCancellation: true,
				FuncWithError: func(ctx context.Context) error {
					<-ctx.Done() // wait for the pipeline to be closed.
					return nil
				},
			},
			work.PipelineStep{
				ID: "2",
				Outputs: map[string]io.Closer{
					"output": output,
				},
				FuncWithError: func(ctx context.Context) error {
					return nil
				},
			},
		)
		require.NoError(t, err)

		require.EventuallyWithT(t, func(collect *assert.CollectT) {
			require.Equal(collect, int64(1), output.calls.Load())
		}, 50*time.Millisecond, 10*time.Millisecond)

		err = p.Close(t.Context())
		require.NoError(t, err)

		// ensure it was only closed once
		require.Equal(t, int64(1), output.calls.Load())
	})

	t.Run("ok, multiple steps share same output, only closes after last step is done", func(t *testing.T) {
		output := newTestCloser(nil)
		closeSignals := make(chan struct{})
		p, err := work.RunPipeline(
			t.Context(),
			work.PipelineStep{
				ID: "1",
				Outputs: map[string]io.Closer{
					"output": output,
				},
				FuncWithError: func(ctx context.Context) error {
					<-closeSignals
					return nil
				},
			},
			work.PipelineStep{
				ID: "2",
				Outputs: map[string]io.Closer{
					"output": output,
				},
				FuncWithError: func(ctx context.Context) error {
					<-closeSignals
					return nil
				},
			},
		)
		require.NoError(t, err)

		// begin with unclosed output
		require.Equal(t, int64(0), output.calls.Load())
		// close one step
		closeSignals <- struct{}{}
		// output still unclosed
		require.Equal(t, int64(0), output.calls.Load())
		// close the other step
		closeSignals <- struct{}{}
		// wait for output to be closed
		require.EventuallyWithT(t, func(collect *assert.CollectT) {
			require.Equal(collect, int64(1), output.calls.Load())
		}, 50*time.Millisecond, 10*time.Millisecond)

		err = p.Close(t.Context())
		require.NoError(t, err)

		// ensure it was only closed once
		require.Equal(t, int64(1), output.calls.Load())
	})

	t.Run("fail, step with empty ID", func(t *testing.T) {
		_, err := work.RunPipeline(
			t.Context(),
			work.PipelineStep{
				ID: "",
				FuncWithError: func(ctx context.Context) error {
					return nil
				},
			},
		)
		require.Error(t, err)
	})

	t.Run("fail, duplicate step IDs", func(t *testing.T) {
		_, err := work.RunPipeline(
			t.Context(),
			work.PipelineStep{
				ID: "step-1",
				FuncWithError: func(ctx context.Context) error {
					return nil
				},
			},
			work.PipelineStep{
				ID: "step-1",
				FuncWithError: func(ctx context.Context) error {
					return nil
				},
			},
		)
		require.Error(t, err)
	})

	t.Run("fail, step with nil step func", func(t *testing.T) {
		_, err := work.RunPipeline(
			t.Context(),
			work.PipelineStep{
				ID:            "step",
				FuncWithError: nil,
			},
		)
		require.Error(t, err)
	})

	t.Run("fail, steps with same id for different outputs", func(t *testing.T) {
		_, err := work.RunPipeline(
			t.Context(),
			work.PipelineStep{
				ID: "1",
				Outputs: map[string]io.Closer{
					"output": newTestCloser(nil),
				},
				FuncWithError: func(ctx context.Context) error {
					return nil
				},
			},
			work.PipelineStep{
				ID: "2",
				Outputs: map[string]io.Closer{
					"output": newTestCloser(nil),
				},
				FuncWithError: func(ctx context.Context) error {
					return nil
				},
			},
		)
		require.Error(t, err)
	})
}

type testCloser struct {
	err   error
	calls *atomic.Int64
}

func newTestCloser(err error) *testCloser {
	return &testCloser{
		err:   err,
		calls: &atomic.Int64{},
	}
}

func (c *testCloser) Close() error {
	c.calls.Add(1)
	return c.err
}
