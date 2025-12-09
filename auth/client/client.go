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

package client

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/cenkalti/backoff/v4"
	"github.com/openpcc/openpcc/ahttp"
	"github.com/openpcc/openpcc/anonpay"
	"github.com/openpcc/openpcc/anonpay/currency"
	"github.com/openpcc/openpcc/auth/credentialing"
	"github.com/openpcc/openpcc/gen/protos"
	"github.com/openpcc/openpcc/httpfmt"
	"github.com/openpcc/openpcc/httpretry"
	"github.com/openpcc/openpcc/otel/otelutil"
	"github.com/openpcc/openpcc/proton"
	"github.com/openpcc/openpcc/transparency"
	"google.golang.org/protobuf/proto"
)

const APIKeyHeader = "cf-authorization"

// DefaultRefillMultiple is how many credits will be requested from Auth at a time.
// When we have set a credit value we can adjust this and make it configurable.
const DefaultRefillMultiple = 40

// Config is the config for the client.
type Config struct {
	BaseURL                    string
	APIKey                     string
	RefillMultiple             int64
	TransparencyIdentityPolicy *transparency.IdentityPolicy
	ConfigRequestMaxTimeout    time.Duration
	CreditRequestMaxTimeout    time.Duration
}

func DefaultConfig() Config {
	return Config{
		BaseURL:                 "",
		APIKey:                  "",
		RefillMultiple:          DefaultRefillMultiple,
		ConfigRequestMaxTimeout: time.Minute,
		CreditRequestMaxTimeout: time.Minute * 5,
	}
}

type BackoffFunc func() backoff.BackOff

type Client struct {
	httpClient           *http.Client
	creditReqBackoffFunc BackoffFunc
	cfg                  Config
	remoteCfg            RemoteConfig
	payee                *anonpay.Payee

	badgeMu *sync.RWMutex
	badge   *credentialing.Badge
}

type TransparencyVerifier interface {
	VerifyStatementPredicate(b []byte, predicateKey string, identity transparency.IdentityPolicy) (*transparency.Statement, transparency.BundleMetadata, error)
}

func New(ctx context.Context, cfg Config, verifier TransparencyVerifier, httpClient *http.Client) (*Client, error) {
	if cfg.APIKey == "" {
		return nil, errors.New("missing API Key")
	}

	slog.Info("fetching remote config from auth server", "base_url", cfg.BaseURL)
	pbRemoteCfg, err := fetchRemoteConfig(ctx, cfg, httpClient)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch remote config: %w", err)
	}

	remoteCfg, currencyKey, err := verifyRemoteConfig(cfg, pbRemoteCfg, verifier)
	if err != nil {
		return nil, fmt.Errorf("failed to verify remote config: %w", err)
	}

	return &Client{
		httpClient: httpClient,
		cfg:        cfg,
		remoteCfg:  remoteCfg,
		payee:      anonpay.NewPayee(currencyKey),
		creditReqBackoffFunc: func() backoff.BackOff {
			return backoff.NewExponentialBackOff(
				backoff.WithMaxElapsedTime(cfg.CreditRequestMaxTimeout),
			)
		},
		badgeMu: &sync.RWMutex{},
	}, nil
}

func (c *Client) RemoteConfig() RemoteConfig {
	return c.remoteCfg
}

func (c *Client) doRetryingCreditRequest(ctx context.Context, value currency.Value, endpoint string) (*anonpay.BlindedCredit, error) {
	unsignedCredit, err := c.payee.BeginBlindedCredit(ctx, value)
	if err != nil {
		return nil, fmt.Errorf("error creating blinded credit: %w", err)
	}

	// Get the credit
	blindedRequest := unsignedCredit.Request()
	pbr, err := blindedRequest.Value.MarshalProto()
	if err != nil {
		return nil, fmt.Errorf("error marshalling blinded request: %w", err)
	}
	withdrawal := protos.AuthWithdrawalRequest_builder{
		ApiKey:         &c.cfg.APIKey,
		Value:          pbr,
		BlindedMessage: blindedRequest.BlindedMessage,
	}.Build()
	withdrawalBytes, err := proto.Marshal(withdrawal)
	if err != nil {
		return nil, fmt.Errorf("error marshalling blinded request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, io.NopCloser(bytes.NewReader(withdrawalBytes)))
	req.Header.Set("Content-Type", "application/octet-stream")
	req.Header.Set(APIKeyHeader, c.cfg.APIKey)
	if err != nil {
		return nil, fmt.Errorf("error building blinded request: %w", err)
	}

	resp, err := httpretry.DoWith(c.httpClient, req, c.creditReqBackoffFunc(), func(rawResp *http.Response) (bool, error) {
		retry, err := httpretry.Retry5xx(rawResp)
		if retry || err != nil {
			return retry, err
		}
		// See TODO below on spend limits.
		if rawResp.StatusCode == http.StatusTooManyRequests {
			slog.Error("spend/request limit reached. retrying...")
			return true, nil
		}
		return false, nil
	})
	if err != nil {
		return nil, fmt.Errorf("credit signing request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		// TODO: More robust spend limit error implemententation. We should return an error that:
		// - Reports the specific spend limit that was violated (organizational or service account).
		// - How many seconds until it resets, so the caller can decide to retry at a later if it's
		//   only a short duration.
		if resp.StatusCode == http.StatusTooManyRequests {
			// For now we retry on this error. As the spend limit may be increased by the user
			// while the wallet is running.
			//
			// Returning a transfer.InsufficientBalanceError so the wallet can properly handle
			// this error when making Optimistic Withdrawals.
			return nil, anonpay.InsufficientBalanceError{
				Balance: -1, // We don't know the actual balance, see the TODO above.
			}
		}

		err = fmt.Errorf("unexpected status code %d", resp.StatusCode)
		return nil, httpfmt.ParseBodyAsError(resp, err)
	}

	withdrawalResponse := protos.AuthWithdrawalResponse{}
	decoder := proton.NewDecoder(resp.Body)
	if err := decoder.Decode(&withdrawalResponse); err != nil {
		return nil, fmt.Errorf("error reading signed blinded credit: %w", err)
	}

	credit, err := unsignedCredit.Finalize(withdrawalResponse.GetBlindSignature())
	if err != nil {
		return nil, fmt.Errorf("failed to finalize blinded credit: %w", err)
	}

	c.badgeMu.Lock()
	defer c.badgeMu.Unlock()
	if c.badge == nil {
		c.badge = &credentialing.Badge{}
		err = (*c.badge).UnmarshalProto(withdrawalResponse.GetBadge())
		if err != nil {
			return nil, fmt.Errorf("failed to parse badge: %w", err)
		}
		err = verifyBadge(c.badge)
		if err != nil {
			c.badge = nil
			return nil, fmt.Errorf("failed to verify badge: %w", err)
		}
	}

	return credit, nil
}

func (c *Client) GetAttestationToken(ctx context.Context) (*anonpay.BlindedCredit, error) {
	return c.doRetryingCreditRequest(ctx, ahttp.AttestationCurrencyValue, c.cfg.BaseURL+"/api/attestationRequest")
}

func verifyBadge(badge *credentialing.Badge) error {
	modelsSeen := make(map[string]struct{})
	for _, model := range badge.Credentials.Models {
		_, seen := modelsSeen[model]
		if seen {
			return fmt.Errorf("found duplicate model in Badge credentials: %s", model)
		}
		modelsSeen[model] = struct{}{}
	}
	return nil
}

func (c *Client) GetBadge(ctx context.Context) (credentialing.Badge, error) {
	ctx, span := otelutil.Tracer.Start(ctx, "auth/client.GetBadge")
	defer span.End()

	c.badgeMu.RLock()
	badge := c.badge
	c.badgeMu.RUnlock()

	if badge == nil {
		// GetAttestation calls makeCurrencyRequest, which populates c.badge
		_, err := c.GetAttestationToken(ctx)
		if err != nil {
			return credentialing.Badge{}, err
		}
	}

	c.badgeMu.RLock()
	badge = c.badge
	c.badgeMu.RUnlock()

	return *badge, nil
}

func (c *Client) GetCredit(ctx context.Context, amountNeeded int64) (*anonpay.BlindedCredit, error) {
	// Round up amountNeeded to multiple of cfg.RefillMultiple
	refillAmount := (amountNeeded + c.cfg.RefillMultiple - 1) / c.cfg.RefillMultiple * c.cfg.RefillMultiple
	amountRoundedUp, err := currency.Rounded(float64(refillAmount), 1)
	if err != nil {
		return nil, fmt.Errorf("error creating credit amount: %d for request: %d, got: %w", refillAmount, amountNeeded, err)
	}

	return c.doRetryingCreditRequest(ctx, amountRoundedUp, c.cfg.BaseURL+"/api/auth")
}

func (c *Client) PutCredit(ctx context.Context, credit *anonpay.BlindedCredit) error {
	creditProto, err := credit.MarshalProto()
	if err != nil {
		return fmt.Errorf("error marshalling credit: %w", err)
	}

	refund := protos.AuthRefundRequest_builder{
		ApiKey: &c.cfg.APIKey,
		Credit: creditProto,
	}.Build()
	refundBytes, err := proto.Marshal(refund)
	if err != nil {
		return fmt.Errorf("error marshalling refund request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.cfg.BaseURL+"/api/refund", io.NopCloser(bytes.NewReader(refundBytes)))
	req.Header.Set("Content-Type", "application/octet-stream")
	req.Header.Set(APIKeyHeader, c.cfg.APIKey)
	if err != nil {
		return fmt.Errorf("error building refund request: %w", err)
	}

	resp, err := httpretry.DoWith(c.httpClient, req, c.creditReqBackoffFunc(), httpretry.Retry5xx)
	if err != nil {
		return fmt.Errorf("error sending refund: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		err = fmt.Errorf("unexpected status code %d", resp.StatusCode)
		return httpfmt.ParseBodyAsError(resp, err)
	}

	return nil
}

func (c *Client) Payee() *anonpay.Payee {
	return c.payee
}
