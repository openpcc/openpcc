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

package httpretry_test

import (
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cenkalti/backoff/v4"
	"github.com/openpcc/openpcc/httpretry"
	test "github.com/openpcc/openpcc/inttest"
	"github.com/stretchr/testify/require"
)

func TestDoFor(t *testing.T) {
	testBackoffFunc := func() backoff.BackOff {
		return backoff.NewExponentialBackOff(backoff.WithMaxElapsedTime(5 * time.Second))
	}

	newClient := func(_ *testing.T) (*http.Client, *countingTransport) {
		transport := &countingTransport{}
		httpClient := &http.Client{
			Timeout:   time.Second * 2,
			Transport: transport,
		}

		return httpClient, transport
	}

	okTests := []int{
		http.StatusOK,
		http.StatusPermanentRedirect,
		http.StatusBadRequest,
	}
	for _, code := range okTests {
		t.Run("ok, "+strconv.Itoa(code)+" response is returned immediately", func(t *testing.T) {
			t.Parallel()

			httpClient, _ := newClient(t)

			var calls atomic.Int64
			serverURL := test.RunHandlerWhile(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				w.WriteHeader(code)
				w.Write([]byte("Hello world!"))
			}))

			req, err := http.NewRequest(http.MethodGet, serverURL, nil)
			require.NoError(t, err)

			resp, err := httpretry.DoWith(httpClient, req, testBackoffFunc(), httpretry.Retry5xx)
			require.NoError(t, err)

			require.Equal(t, resp.StatusCode, code)
			test.RequireReadAll(t, []byte("Hello world!"), resp.Body)
			err = resp.Body.Close()
			require.NoError(t, err)
			require.Equal(t, int64(1), calls.Load()) // single call

			// verify the response is linked to the original request
			require.Same(t, req, resp.Request)
		})
	}

	t.Run("ok, retry 500 status", func(t *testing.T) {
		t.Parallel()

		httpClient, _ := newClient(t)

		var calls atomic.Int64
		serverURL := test.RunHandlerWhile(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			calls.Add(1)
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte("Hello world!"))
		}))

		req, err := http.NewRequest(http.MethodGet, serverURL, nil)
		require.NoError(t, err)

		resp, err := httpretry.DoWith(httpClient, req, testBackoffFunc(), httpretry.Retry5xx)
		require.NoError(t, err)

		require.Equal(t, resp.StatusCode, http.StatusInternalServerError)
		test.RequireReadAll(t, []byte("Hello world!"), resp.Body)
		err = resp.Body.Close()
		require.NoError(t, err)
		require.GreaterOrEqual(t, calls.Load(), int64(2)) // want at least 2 calls.

		// verify the response is linked to the original request
		require.Same(t, req, resp.Request)
	})

	t.Run("ok, retry request with body", func(t *testing.T) {
		t.Parallel()

		httpClient, _ := newClient(t)

		var calls atomic.Int64
		serverURL := test.RunHandlerWhile(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			test.AssertReadAll(t, []byte("Hello world!"), r.Body)
			calls.Add(1)
			w.WriteHeader(http.StatusInternalServerError) // to trigger retry.
		}))

		// need a reader that the http client doesn't do any special handling for.
		mr := io.MultiReader(strings.NewReader(`Hello world!`))

		req, err := http.NewRequest(http.MethodPost, serverURL, mr)
		require.NoError(t, err)

		resp, err := httpretry.DoWith(httpClient, req, testBackoffFunc(), httpretry.Retry5xx)
		require.NoError(t, err)

		require.Equal(t, resp.StatusCode, http.StatusInternalServerError)
		require.GreaterOrEqual(t, calls.Load(), int64(2)) // want at least 2 calls.

		// verify the response is linked to the original request
		require.Same(t, req, resp.Request)
	})

	t.Run("ok, retry connection refused", func(t *testing.T) {
		t.Parallel()

		httpClient, transport := newClient(t)

		port := test.FreePort(t)
		serverURL := fmt.Sprintf("http://127.0.0.1:%d", port)

		req, err := http.NewRequest(http.MethodGet, serverURL, nil)
		require.NoError(t, err)

		_, err = httpretry.DoWith(httpClient, req, testBackoffFunc(), httpretry.Retry5xx)
		require.Error(t, err)

		require.GreaterOrEqual(t, transport.calls.Load(), int64(2)) // want at least 2 calls.
	})

	t.Run("fail, url error is not retried", func(t *testing.T) {
		t.Parallel()

		httpClient, transport := newClient(t)

		serverURL := "example.com" // missing protocol

		req, err := http.NewRequest(http.MethodGet, serverURL, nil)
		require.NoError(t, err)

		_, err = httpretry.DoWith(httpClient, req, testBackoffFunc(), httpretry.Retry5xx)
		require.Error(t, err)

		require.GreaterOrEqual(t, transport.calls.Load(), int64(1)) // want single call
	})
}

type countingTransport struct {
	calls atomic.Int64
}

func (t *countingTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	t.calls.Add(1)
	return http.DefaultTransport.RoundTrip(r)
}
