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

package httpapi

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/cenkalti/backoff/v4"
	"github.com/openpcc/openpcc/anonpay"
	pb "github.com/openpcc/openpcc/gen/protos/anonpay/noncelocking"
	"github.com/openpcc/openpcc/httpretry"
	"github.com/openpcc/openpcc/otel/otelutil"
	"github.com/openpcc/openpcc/proton"
	"go.opentelemetry.io/otel/codes"
	"google.golang.org/protobuf/proto"
)

type HTTPClient interface {
	Do(req *http.Request) (*http.Response, error)
}

type BackoffFunc func() backoff.BackOff

type Client struct {
	httpClient  HTTPClient
	baseURL     string
	backoffFunc BackoffFunc
}

func NewClient(httpClient HTTPClient, baseURL string) *Client {
	return NewClientWithBackoff(httpClient, baseURL, func() backoff.BackOff {
		return backoff.NewExponentialBackOff(
			backoff.WithMaxElapsedTime(3 * time.Minute),
		)
	})
}

func NewClientWithBackoff(httpClient HTTPClient, baseURL string, b BackoffFunc) *Client {
	return &Client{
		baseURL:     baseURL,
		httpClient:  httpClient,
		backoffFunc: b,
	}
}

func (c *Client) LockNonce(ctx context.Context, nonce anonpay.Nonce) (string, error) {
	_, span := otelutil.Tracer.Start(ctx, "anonpay.noncelocking.httpapi.LockNonce")
	defer span.End()

	lockReq := pb.LockRequest_builder{
		Nonce: nonce.MarshalProto(),
	}.Build()

	lockResp := &pb.LockResponse{}

	err := c.doRequest(ctx, "/lock", lockReq, lockResp)
	if err != nil {
		return "", otelutil.Errorf(span, "failed to send lock request: %w", err)
	}

	span.SetStatus(codes.Ok, "")

	return lockResp.GetTicket(), nil
}

func (c *Client) ConsumeNonce(ctx context.Context, nonce anonpay.Nonce, ticket string) error {
	_, span := otelutil.Tracer.Start(ctx, "anonpay.noncelocking.httpapi.ConsumeNonce")
	defer span.End()

	lockReq := pb.UnlockRequest_builder{
		Nonce:  nonce.MarshalProto(),
		Ticket: &ticket,
	}.Build()

	err := c.doRequest(ctx, "/consume", lockReq, nil)
	if err != nil {
		return otelutil.Errorf(span, "failed to send consume request: %w", err)
	}

	span.SetStatus(codes.Ok, "")

	return nil
}

func (c *Client) ReleaseNonce(ctx context.Context, nonce anonpay.Nonce, ticket string) error {
	_, span := otelutil.Tracer.Start(ctx, "anonpay.noncelocking.httpapi.ReleaseNonce")
	defer span.End()

	lockReq := pb.UnlockRequest_builder{
		Nonce:  nonce.MarshalProto(),
		Ticket: &ticket,
	}.Build()

	err := c.doRequest(ctx, "/release", lockReq, nil)
	if err != nil {
		return otelutil.Errorf(span, "failed to send release request: %w", err)
	}

	span.SetStatus(codes.Ok, "")

	return nil
}

func (c *Client) doRequest(ctx context.Context, endpoint string, reqPB proto.Message, outPB proto.Message) error {
	reqBytes, err := proto.Marshal(reqPB)
	if err != nil {
		return fmt.Errorf("failed to marshal request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+endpoint, bytes.NewReader(reqBytes))
	req.Header.Set("Content-Type", "application/octet-stream")
	if err != nil {
		return fmt.Errorf("failed to create http request: %w", err)
	}

	resp, err := httpretry.DoWith(c.httpClient, req, c.backoffFunc(), httpretry.Retry5xx)
	if err != nil {
		return fmt.Errorf("http request failed: %w", err)
	}
	defer func() {
		closeErr := resp.Body.Close()
		err = errors.Join(err, closeErr)
	}()

	if resp.StatusCode != http.StatusOK {
		err = fmt.Errorf("unexpected status code from blind bank: %d for %s", resp.StatusCode, endpoint)
		switch resp.StatusCode {
		case http.StatusBadRequest:
			return anonpay.InputError{
				Err: err,
			}
		case http.StatusGone:
			return anonpay.ErrNonceConsumed
		case http.StatusConflict:
			return anonpay.ErrNonceLocked
		default:
			return err
		}
	}

	if outPB != nil {
		decoder := proton.NewDecoder(resp.Body)
		if err := decoder.Decode(outPB); err != nil {
			return fmt.Errorf("failed to decode response: %w", err)
		}
	}

	return nil
}
