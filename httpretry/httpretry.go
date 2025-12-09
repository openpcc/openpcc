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

package httpretry

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/cenkalti/backoff/v4"
)

var (
	err500 = errors.New("500 status")
)

type HTTPDoer interface {
	Do(*http.Request) (*http.Response, error)
}

// CheckFunc determines if a response needs a retry.
type CheckFunc func(r *http.Response) (bool, error)

func Retry5xx(r *http.Response) (bool, error) {
	return r.StatusCode >= 500, nil
}

// Do retries the given request until it succeeds, a permanent error is encountered
// or it has been retried for the default backoff. Responses with status code 500 are also retried.
//
// Do retries the given request using the default backoff. The request succeeds when no
// network errors are encountered and the response has a non 5xx status code.
//
// The body of the request is copied before any retries are made.
func Do(c HTTPDoer, req *http.Request) (*http.Response, error) {
	boff := backoff.NewExponentialBackOff(
		backoff.WithMaxElapsedTime(3 * time.Minute),
	)
	return DoWith(c, req, boff, Retry5xx)
}

// DoWith retries the given request until:
// - The request context is cancelled.
// - A non-network error is encountered in the HTTPDoer.
// - The provided backoff stops.
// - The CheckFunc determines a response is suitable.
//
// The body of the request is copied on the first use and the body of the most
// recent response that didn't pass the CheckFunc is stored in memory as well.
//
// If CheckFunc returns an error, it should make sure to close the body on the response.
func DoWith(c HTTPDoer, req *http.Request, b backoff.BackOff, checkFunc CheckFunc) (*http.Response, error) {
	var (
		result         *http.Response
		rewindableBody *rewindableBody
		last500Body    = &bytes.Buffer{}
	)

	if req.Body != nil && req.Body != http.NoBody {
		rewindableBody = newRewindableBody(req.Body)
		req.Body = rewindableBody
	}

	i := 0
	finalErr := backoff.Retry(func() error {
		defer func() {
			i++
		}()

		// clone request and re-use the rewindable body if one was set.
		retryReq := req.Clone(req.Context())
		if rewindableBody != nil && i > 0 {
			err := rewindableBody.Rewind()
			if err != nil {
				return backoff.Permanent(fmt.Errorf("failed to rewind body: %w", err))
			}

			retryReq.Body = rewindableBody
		}

		resp, err := c.Do(retryReq)
		if err != nil {
			if errors.Is(err, context.Canceled) {
				return backoff.Permanent(err)
			}

			var netErr net.Error
			if errors.As(err, &netErr) {
				if netErr.Timeout() || strings.Contains(netErr.Error(), "connection refused") {
					// retry timeouts and refused connections (service might be starting up).
					return err
				}
				return backoff.Permanent(err)
			}

			return backoff.Permanent(err)
		}

		// save the last response
		result = resp
		result.Request = req // link the original request.

		retry, err := checkFunc(resp)
		if err != nil {
			// check func returned an error, it's responsible for closing the response body.
			return backoff.Permanent(fmt.Errorf("failed to check response for retry: %w", err))
		}

		if retry {
			// drain the body.
			last500Body.Reset()
			_, err := io.Copy(last500Body, result.Body)
			if err != nil {
				return fmt.Errorf("failed to read body: %w", err)
			}

			err = result.Body.Close()
			if err != nil {
				return fmt.Errorf("failed to close response body: %w", err)
			}

			// save the body.
			result.Body = io.NopCloser(last500Body)

			return err500
		}

		return nil
	}, backoff.WithContext(
		b,
		req.Context(),
	))

	// don't pass on errors due to 500 status codes.
	if errors.Is(finalErr, err500) {
		return result, nil
	}

	return result, finalErr
}

type rewindableBody struct {
	waitForOrigCloseOnce *sync.Once
	origCloseDone        chan error
	origCloseErr         error
	origClosed           bool

	orig      io.ReadCloser
	buffer    *bytes.Buffer
	recording *bytes.Reader
	teeR      io.Reader
}

func newRewindableBody(orig io.ReadCloser) *rewindableBody {
	buf := &bytes.Buffer{}
	return &rewindableBody{
		waitForOrigCloseOnce: &sync.Once{},
		origCloseDone:        make(chan error, 1),
		origCloseErr:         nil,
		origClosed:           false,

		orig: orig,
		// teeR will copy from original to buffer.
		teeR:   io.TeeReader(orig, buf),
		buffer: buf,
		// recording will be set once the original is closed.
		recording: nil,
	}
}

// Rewind waits for the body to be closed and rewinds the recorded body.
func (c *rewindableBody) Rewind() error {
	c.waitForOrigCloseOnce.Do(func() {
		c.origCloseErr = <-c.origCloseDone
		c.recording = bytes.NewReader(c.buffer.Bytes())
	})

	if c.origCloseErr != nil {
		return fmt.Errorf("can't rewind body that failed to close: %w", c.origCloseErr)
	}

	_, err := c.recording.Seek(0, io.SeekStart)
	if err != nil {
		return fmt.Errorf("failed to seek to beginning: %w", err)
	}
	return nil
}

func (c *rewindableBody) Read(p []byte) (int, error) {
	if c.origCloseErr != nil {
		return 0, fmt.Errorf("can't read from body that failed to close: %w", c.origCloseErr)
	}

	if c.origClosed {
		return c.recording.Read(p)
	}

	// read from the teeReader so we record the original data as it is read.
	return c.teeR.Read(p)
}

func (c *rewindableBody) Close() error {
	if c.origClosed {
		return c.origCloseErr
	}

	err := c.orig.Close()
	c.origCloseDone <- err
	close(c.origCloseDone)
	c.origClosed = true
	return err
}
