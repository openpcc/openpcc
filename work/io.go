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
	"io"
)

var ErrInputClosed = errors.New("input closed")

// DropErrClosed is a helper function that drops ErrInputClosed errors.
func DropErrInputClosed(err error) error {
	if errors.Is(err, ErrInputClosed) {
		return nil
	}
	return err
}

// ReceiveInput is a helper function that either:
// - Returns a value received from c.
// - Returns [ErrInputClosed] if c is closed.
// - Returns an error when the context is done before that.
//
// This makes receiving input in workers less repetitive, as this is a common pattern.
func ReceiveInput[T any](ctx context.Context, c <-chan T) (T, error) {
	select {
	case val, ok := <-c:
		if !ok {
			return val, ErrInputClosed
		}
		return val, nil
	case <-ctx.Done():
		var val T
		return val, ctx.Err()
	}
}

// DrainInput drains the provided input channel.
func DrainInput[T any](c <-chan T, rcvFunc func(T)) {
	if c == nil {
		return
	}

	for val := range c {
		if rcvFunc != nil {
			rcvFunc(val)
		}
	}
}

// Channel is a helper type that can be used to create a named channel
// that can be closed by the pipeline when provided as Output on a worker.
//
// When using the channel to connect pipeline workers, the general pattern is that
// sending workers will write to the channel without waiting for contexts to be done.
//
// The receiving worker should check if the context is done, and if it is, drain the
// channels it receives from.
type Channel[T any] struct {
	id        string
	ReceiveCh <-chan T
	SendCh    chan<- T
	ch        chan T
}

func NewChannel[T any](id string, capacity int) *Channel[T] {
	ch := make(chan T, capacity)
	return &Channel[T]{
		id:        id,
		ReceiveCh: ch,
		SendCh:    ch,
		ch:        ch,
	}
}

func (c *Channel[T]) IsSet() bool {
	return c != nil
}

func (c *Channel[T]) ID() string {
	return c.id
}

func (c *Channel[T]) Receive(ctx context.Context) (T, error) {
	return ReceiveInput(ctx, c.ReceiveCh)
}

func (c *Channel[T]) Close() error {
	close(c.ch)
	return nil
}

// MustHaveInput is a helper function that panics early with a clear message when
// we provide a nil input somewhere we shouldn't.
func MustHaveInput[T any](stepID string, in <-chan T) {
	if in == nil {
		panic(fmt.Sprintf("dev error: required input of type %T in step %s is not set", in, stepID))
	}
}

type Output interface {
	ID() string
	IsSet() bool
	io.Closer
}

// MustHaveOutput is a helper function that panics early with a clear message when
// we provide a nil output somewhere we shouldn't.
func MustHaveOutput[T any](stepID string, output Output) {
	if !output.IsSet() {
		panic(fmt.Sprintf("dev error: required output of type %T in step %s is not set", output, stepID))
	}
}

// StepOutputs is a helper function that combines separate inputs in the format
// expected by a pipeline step.
func StepOutputs(outputs ...Output) map[string]io.Closer {
	combined := map[string]io.Closer{}
	for _, output := range outputs {
		if !output.IsSet() {
			continue
		}
		combined[output.ID()] = output
	}
	return combined
}
