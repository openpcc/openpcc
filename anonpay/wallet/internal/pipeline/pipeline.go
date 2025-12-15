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

	"github.com/openpcc/openpcc/work"
)

type RootStep struct {
	ID string
	// nolint:revive
	DoneOutput *work.Channel[struct{}]
	// HandleUnrecoverableError is called when the pipeline closes
	// due to an error that's not [work.ErrPipelineClosed].
	//
	// A context that is done and has [work.ErrPipelineClosed] as a cause
	// signals a clean exit. During a clean exit, the pipeline will close
	// input channels to signal that no more work items will be provided.
	// Workers can then exit in turn.
	//
	// A context that is done and has a different cause, means that one of
	// the downstream workers exited early. This is an unrecoverable error,
	// as we can't shut down the pipeline cleanly with missing workers.
	HandleUnrecoverableError func(err error)
}

func NewRootStep(s *RootStep) work.PipelineStep {
	work.MustHaveOutput[struct{}](s.ID, s.DoneOutput)
	return work.PipelineStep{
		ID:                          s.ID,
		Outputs:                     work.StepOutputs(s.DoneOutput),
		ReceivePipelineCancellation: true,
		FuncWithError: func(ctx context.Context) error {
			<-ctx.Done()
			err := work.DropErrPipelineClosed(ctx, context.Cause(ctx))
			if err != nil && s.HandleUnrecoverableError != nil {
				s.HandleUnrecoverableError(err)
			}
			return err
		},
	}
}

type pipelineSteps []work.PipelineStep

func (s *pipelineSteps) add(steps ...work.PipelineStep) {
	*s = append(*s, steps...)
}
