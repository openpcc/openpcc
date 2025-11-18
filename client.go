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
package openpcc

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/cloudflare/circl/hpke"
	obhttp "github.com/confidentsecurity/ohttp/encoding/bhttp"
	"github.com/openpcc/openpcc/ahttp"
	"github.com/openpcc/openpcc/anonpay"
	"github.com/openpcc/openpcc/anonpay/banking/httpapi"
	"github.com/openpcc/openpcc/anonpay/currency"
	"github.com/openpcc/openpcc/anonpay/wallet"
	authclient "github.com/openpcc/openpcc/auth/client"
	"github.com/openpcc/openpcc/auth/credentialing"
	"github.com/openpcc/openpcc/chunk"
	"github.com/openpcc/openpcc/gateway"
	"github.com/openpcc/openpcc/router/api"
	"github.com/openpcc/openpcc/tags"
	"github.com/openpcc/openpcc/transparency"

	"github.com/confidentsecurity/ohttp"
	"github.com/confidentsecurity/twoway"
	"github.com/google/uuid"
	"github.com/openpcc/openpcc/gen/protos"
	"github.com/openpcc/openpcc/httpfmt"
	"github.com/openpcc/openpcc/messages"
	"github.com/openpcc/openpcc/models"
	"github.com/openpcc/openpcc/otel/otelutil"
	"github.com/openpcc/openpcc/uuidv7"
	"go.opentelemetry.io/otel/codes"
	"google.golang.org/protobuf/proto"
)

const (
	// OHTTP Gateway requires external requests for these services
	// to use these urls.
	// revive:disable:unsecure-url-scheme
	externalBankURL   = "http://confsec-bank.invalid"
	externalRouterURL = "http://confsec-router.invalid"
)

var (
	// DefaultNonAnonTransport is the default transport used by the confsec client.
	DefaultNonAnonTransport = chunk.NewHTTPTransport(defaultHTTPDialTimeout)

	// DefaultNonAnonHTTPClient is the default HTTP client used for non-anonimized requests. This
	// includes, for example, requests to the auth service and the transparency log. It is also used
	// as the underlying transport when making OHTTP requests with anonHTTPClient.
	DefaultNonAnonHTTPClient = &http.Client{
		Timeout:   defaultHTTPClientTimeout,
		Transport: otelutil.NewTransport(DefaultNonAnonTransport),
	}
)

// Client facilitates private and secure communication with compute nodes.
//
// Client implements [http.RoundTripper] and can be used as a transport in a [http.Client].
//
// Alternatively, call [Client.HTTPClient] to get a ready-to-use [http.Client].
//
// It's important to read the bodies of responses until you encounter [io.EOF]. Refunds are
// attached at the end of these response bodies and this is the only way the client can process
// them.
//
// Similarly, it's important to always call [Client.Close] after you're done using the client. Even
// in case of errors. This will ensure proper cleanup of unspend credits.
//
// All request made with a client should use confsec.invalid as the hostname. The .invalid top-level
// domain is not resolvable and will ensure that requests won't get routed anywhere in case of
// configuration errors. Request made for other hostnames will cause an error.
type Client struct {
	mu                        *sync.RWMutex
	params                    RequestParams
	requestParamsFunc         RequestParamsFunc
	wallet                    Wallet
	walletCloseTimeout        time.Duration
	nodeFinder                VerifiedNodeFinder
	routerURL                 string
	maxCandidateNodes         int
	maxCreditAmountPerRequest int64
	// anonHTTPClient is used to make requests which should be anonimized.
	anonHTTPClient *http.Client
	// nonAnonHTTPClient is used to make regular requests.
	nonAnonHTTPClient    *http.Client
	requestSender        *twoway.MultiRequestSender
	transparencyVerifier TransparencyVerifier
	relayURL             string
}

// New creates a new Client and begins fetching resources.
func New(ctx context.Context, apiKey string, opts ...Option) (*Client, error) {
	cfg := DefaultConfig()
	cfg.APIKey = apiKey
	return NewFromConfig(ctx, cfg, opts...)
}

func NewFromConfig(ctx context.Context, cfg Config, opts ...Option) (*Client, error) {
	ctx, span := otelutil.Tracer.Start(ctx, "client.NewFromConfig")
	defer span.End()

	if cfg.APIURL == "" {
		return nil, errors.New("missing auth API url")
	}
	slog.Info("creating openpcc client with auth server url", "api_url", cfg.APIURL)

	if cfg.TransparencyIdentityPolicySource == IdentityPolicySourceConfigured {
		if cfg.TransparencyIdentityPolicy == nil {
			return nil, errors.New("transparency identity policy source is 'configured' but no policy was provided")
		}
		if cfg.TransparencyIdentityPolicy.OIDCIssuer == "" && cfg.TransparencyIdentityPolicy.OIDCIssuerRegex == "" {
			return nil, errors.New("transparency identity policy source is 'configured' but no issuer or issuer regex was provided")
		}
		if cfg.TransparencyIdentityPolicy.OIDCSubject == "" && cfg.TransparencyIdentityPolicy.OIDCSubjectRegex == "" {
			return nil, errors.New("transparency identity policy source is 'configured' but no subject or subject regex was provided")
		}
	}

	suite := hpke.NewSuite(hpke.KEM_P256_HKDF_SHA256, hpke.KDF_HKDF_SHA256, hpke.AEAD_AES128GCM)

	// Parse the default tags (if any)
	nodeTags := slices.Clone(cfg.DefaultRequestParams.NodeTags)
	defaultTags, err := tags.FromSlice(nodeTags)
	if err != nil {
		return nil, fmt.Errorf("invalid default tags: %w", err)
	}

	// The default credit amount per request is determined in the following order:
	//   1. If cfg.DefaultRequestParams.CreditAmount is set, use that
	//   2. If the caller specified a default model via node tags, use the context length
	//      of that model to derive the credit amount
	//   3. Otherwise, use the longest context length of all supported models to derive
	//      the credit amount
	creditAmount := cfg.DefaultRequestParams.CreditAmount

	if creditAmount == 0 {
		modelTags := defaultTags.GetValues("model")
		switch len(modelTags) {
		case 0:
			creditAmount = models.GetMaxCreditAmountPerRequest()
		case 1:
			_, err := models.GetModel(modelTags[0])
			if err != nil {
				return nil, err
			}
			// TODO: re-enable setting creditAmount based on the default model size, once the wallet's
			// SetDefaultCreditLimit function is implemented
			// creditAmount = defaultModel.GetMaxCreditAmountPerRequest()
			creditAmount = models.GetMaxCreditAmountPerRequest()
		default:
			return nil, fmt.Errorf("multiple models specified in default node tags: %v", modelTags)
		}
	}

	creditAmount, err = RoundCreditAmount(creditAmount)
	if err != nil {
		return nil, err
	}

	// The max credit amount per request is determined in the following order:
	//   1. If cfg.MaxCreditAmountPerRequest is set, use that
	//   2. Otherwise, use the longest context length of all supported models to derive
	//      the max credit amount
	maxCreditAmount := cfg.MaxCreditAmountPerRequest
	if maxCreditAmount == 0 {
		maxCreditAmount = models.GetMaxCreditAmountPerRequest()
	}
	maxCreditAmount, err = RoundCreditAmount(maxCreditAmount)
	if err != nil {
		return nil, err
	}

	c := &Client{
		mu: &sync.RWMutex{},
		params: RequestParams{
			CreditAmount: creditAmount,
			NodeTags:     nodeTags,
		},
		maxCandidateNodes:         cfg.MaxCandidateNodes,
		requestParamsFunc:         RequestParamsFromConfSecHeaders,
		routerURL:                 externalRouterURL,
		maxCreditAmountPerRequest: maxCreditAmount,
		requestSender:             twoway.NewMultiRequestSender(suite, rand.Reader),
		// httpClient is the non-anonimized http client.
		nonAnonHTTPClient:  DefaultNonAnonHTTPClient,
		walletCloseTimeout: cfg.WalletCloseTimeout,
	}

	// temporary scratch for things we need during configuration/initialization
	// but aren't part of config or Client.
	temp := &scratch{}

	for _, opt := range opts {
		err := opt(c, temp, &cfg)
		if err != nil {
			return nil, err
		}
	}

	if c.maxCandidateNodes < 1 {
		return nil, fmt.Errorf("max candidate nodes should be at least 1, got %d", c.maxCandidateNodes)
	}

	if cfg.APIKey == "" {
		return nil, errors.New("missing api key")
	}

	err = c.validateCreditAmount(c.params.CreditAmount)
	if err != nil {
		return nil, err
	}

	if c.transparencyVerifier == nil {
		verifier, err := transparency.NewVerifier(cfg.TransparencyVerifier, c.nonAnonHTTPClient)
		if err != nil {
			return nil, fmt.Errorf("failed to create sigstore bundle verifier: %w", err)
		}
		c.transparencyVerifier = transparency.NewCachedVerifier(verifier)
	}

	// Source the auth client from the right place if it's required.
	makeAuthClient := func() (AuthClient, error) {
		if temp.authClient != nil {
			return temp.authClient, nil
		}

		authCfg := authclient.DefaultConfig()
		authCfg.APIKey = cfg.APIKey
		authCfg.BaseURL = cfg.APIURL
		authCfg.TransparencyIdentityPolicy = cfg.TransparencyIdentityPolicy
		instance, err := authclient.New(ctx, authCfg, c.transparencyVerifier, c.nonAnonHTTPClient)
		if err != nil {
			return nil, fmt.Errorf("failed to create auth client: %w", err)
		}
		temp.authClient = instance
		return temp.authClient, nil
	}

	// Load router URL from auth config unless specified in local config or options.
	if c.routerURL == "" {
		authClient, err := makeAuthClient()
		if err != nil {
			return nil, err
		}
		c.routerURL = authClient.RemoteConfig().RouterURL
	}
	if c.routerURL == "" {
		return nil, errors.New("missing router url")
	}

	// Unless a custom anon http client is provided, we create an anonimized http client
	// by wrapping the base http client with an OHTTP Transport+http client.
	if c.anonHTTPClient == nil {
		authClient, err := makeAuthClient()
		if err != nil {
			return nil, err
		}

		c.relayURL = authClient.RemoteConfig().OHTTPRelayURLs[0]
		if cfg.OHTTPRelayURL != "" {
			c.relayURL = cfg.OHTTPRelayURL
		}
		keyConfigs := authClient.RemoteConfig().OHTTPKeyConfigs
		// Using the available key rotation periods, select the most recently "activated" key config (but not any keys pending activation).
		// TODO(CS-1015): Refactor this into a reusable helper in the keyrotation package.
		keyRotationPeriods := authClient.RemoteConfig().OHTTPKeyRotationPeriods

		validKeys := slices.DeleteFunc(slices.Clone(keyRotationPeriods), func(m gateway.KeyRotationPeriodWithID) bool {
			// Ensure we don't use any keys that are not active,
			// including those that are pending activation, and those that are expired).
			return !m.IsActive()
		})
		if len(validKeys) == 0 {
			return nil, errors.New("no active OHTTP keys available")
		}

		desiredKey := slices.MaxFunc(validKeys, func(a, b gateway.KeyRotationPeriodWithID) int {
			// Important that we find the latest and greatest key to avoid clients using soon-to-expired keys.
			return a.ActiveFrom.Compare(b.ActiveFrom)
		})
		desiredKeyConfigID := desiredKey.KeyID

		// Map the key config ID back to the actual key config.
		idx := slices.IndexFunc(keyConfigs, func(kc ohttp.KeyConfig) bool {
			return kc.KeyID == desiredKeyConfigID
		})
		if idx == -1 {
			return nil, fmt.Errorf("no key config found for key ID %d", desiredKeyConfigID)
		}
		desiredKeyConfig := keyConfigs[idx]

		reqEncoder, err := obhttp.NewRequestEncoder(
			obhttp.FixedLengthRequestChunks(),
			obhttp.MaxRequestChunkLen(messages.EncapsulatedChunkLen()),
		)
		if err != nil {
			return nil, fmt.Errorf("failed to create ohttp request encoder: %w", err)
		}

		ohttpTransport, err := ohttp.NewTransport(
			desiredKeyConfig,
			c.relayURL,
			ohttp.WithHTTPClient(c.nonAnonHTTPClient),
			ohttp.WithRequestEncoder(reqEncoder),
		)
		if err != nil {
			return nil, fmt.Errorf("failed to create ohttp transport: %w", err)
		}

		c.anonHTTPClient = &http.Client{
			Timeout:   defaultHTTPClientTimeout,
			Transport: ohttpTransport,
		}
	}

	if cfg.PingRouter {
		err := c.pingRouter(ctx, 10)
		if err != nil {
			return nil, fmt.Errorf("failed to ping router: %w", err)
		}
	}

	if c.wallet == nil {
		// no payment method provided, set up the default wallet using depCfg.
		authClient, err := makeAuthClient()
		if err != nil {
			return nil, err
		}

		payee := authClient.Payee()
		// note: the bank uses the anonimized http client.
		blindBankClient, err := httpapi.NewClient(c.anonHTTPClient, externalBankURL)
		if err != nil {
			return nil, fmt.Errorf("failed to create blind bank client: %w", err)
		}

		sourceAmount, err := currency.Rounded(float64(c.params.CreditAmount)*10, 1.0)
		if err != nil {
			return nil, fmt.Errorf("failed to create source amount of currency: %w", err)
		}

		w, err := wallet.New(
			wallet.Config{
				SourceAmount:   sourceAmount.AmountOrZero(),
				PrefetchAmount: c.params.CreditAmount,
				MaxParallel:    cfg.ConcurrentRequestsTarget,
			},
			payee,
			blindBankClient,
			wallet.NewWallet1SourceService(authClient),
		)
		if err != nil {
			return nil, fmt.Errorf("failed to create wallet: %w", err)
		}

		c.wallet = w
	}

	if c.nodeFinder == nil {
		// no nodeFinder provided, set up the default node finder using depCfg.
		authClient, err := makeAuthClient()
		if err != nil {
			return nil, err
		}

		// `newVerifier` uses a different implementation depending on the fake_attestation build tag.
		// This build tag is only intended for local development as we can't attest a local machine.
		// For all other environments real attestation is used.
		nodeVerifier := newVerifier(cfg, c.transparencyVerifier)

		simpleNodeFinder := &simpleNodeFinder{
			httpClient:    c.anonHTTPClient,
			authClient:    authClient,
			verifier:      nodeVerifier,
			routerBaseURL: c.routerURL,
		}

		// create cached node finder that can cache nodes for any tag combination
		cachedCfg := DefaultCachedNodeFinderConfig()
		c.nodeFinder = NewCachedNodeFinder(simpleNodeFinder, cachedCfg)
	}

	return c, nil
}

// WalletStatus returns the status of the wallet.
func (c *Client) WalletStatus() wallet.Status {
	return c.wallet.Status()
}

func (c *Client) CachedStatements() []transparency.Statement {
	return c.transparencyVerifier.CachedStatements()
}

// CachedVerifiedNodes returns a list of verified nodes if it has any that are cached presently.
func (c *Client) CachedVerifiedNodes() ([]VerifiedNode, error) {
	return c.nodeFinder.ListCachedVerifiedNodes()
}

func (c *Client) RelayURL() string {
	return c.relayURL
}

// DefaultRequestParams returns the current default request parameters.
func (c *Client) DefaultRequestParams() RequestParams {
	c.mu.RLock()
	defer c.mu.RUnlock()

	return c.params
}

// MaxCreditAmountPerRequest returns the maximum credit amount per request.
func (c *Client) MaxCreditAmountPerRequest() int64 {
	c.mu.RLock()
	defer c.mu.RUnlock()

	return c.maxCreditAmountPerRequest
}

// SetDefaultCreditAmountPerRequest updates the default per-request credit amount of the
// client. All requests made after this call will use this amount unless a request has a
// custom amount.
//
// If this limit is over the MaxCreditAmount [ErrMaxCreditAmountViolated] will be returned.
func (c *Client) SetDefaultCreditAmountPerRequest(limit int64) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	return c.setDefaultCreditAmountPerRequestUnsafe(limit)
}

// setDefaultCreditAmountPerRequestUnsafe is the internal, non-locking version of
// [Client.SetDefaultCreditAmountPerRequest]. Callers should ensure that they acquire
// the Client lock before calling this method.
func (c *Client) setDefaultCreditAmountPerRequestUnsafe(limit int64) error {
	err := c.validateCreditAmount(limit)
	if err != nil {
		return err
	}

	err = c.wallet.SetDefaultCreditAmount(limit)
	if err != nil {
		return err
	}

	c.params.CreditAmount = limit

	return nil
}

func (c *Client) validateCreditAmount(limit int64) error {
	if limit < 1 {
		return fmt.Errorf(
			"credit amount is zero or negative (%d), should be 1 or more",
			limit,
		)
	}

	if limit > c.maxCreditAmountPerRequest {
		return fmt.Errorf(
			"credit amount (%d) is over max credit amount (%d), either specify a lower credit amount or create a client with a higher maximum: %w",
			limit,
			c.maxCreditAmountPerRequest,
			ErrMaxCreditAmountViolated,
		)
	}

	return nil
}

// SetDefaultNodeTags updates the default node tags of the client. All requests
// made after this call will use these tags unless a request has custom tags.
func (c *Client) SetDefaultNodeTags(tagslist []string) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	return c.setDefaultNodeTagsUnsafe(tagslist)
}

// setDefaultNodeTagsUnsafe is the internal, non-locking version of
// [Client.SetDefaultNodeTags]. Callers should ensure that they acquire the Client lock
// before calling this method.
func (c *Client) setDefaultNodeTagsUnsafe(tagslist []string) error {
	c.params.NodeTags = slices.Clone(tagslist)

	newTags, err := tags.FromSlice(c.params.NodeTags)
	if err != nil {
		return err
	}

	// TODO: re-enable setting creditAmountPerRequest once the wallet's SetDefaultCreditAmount
	// function is implemented
	// Check if the default credit amount per request should be updated due to a default
	// model change.
	// var creditAmountPerRequest int64
	modelTags := newTags.GetValues("model")
	switch len(modelTags) {
	case 0:
	// 	creditAmountPerRequest = c.params.CreditAmount
	case 1:
		_, err := models.GetModel(modelTags[0])
		if err != nil {
			return err
		}
		// creditAmountPerRequest = newModel.GetMaxCreditAmountPerRequest()
	default:
		return fmt.Errorf("multiple models specified in default node tags: %v", modelTags)
	}

	// If we need to update the default credit amount per request, do so.
	// if creditAmountPerRequest != c.params.CreditAmount {
	// 	err := c.setDefaultCreditAmountPerRequestUnsafe(creditAmountPerRequest)
	// 	if err != nil {
	// 		return err
	// 	}
	// }

	// Node finders are responsible for handling different sets of tags as they are provided, no further work needs to be done here.
	return nil
}

// TODO: move this model-aware function out of Client and into confsec wrapper
func (c *Client) SetDefaultModel(model string) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	reqTags, err := tags.FromSlice(c.params.NodeTags)
	if err != nil {
		return errors.New("failed to convert tags list to Tags")
	}

	_ = reqTags.RemoveKey("model")
	err = reqTags.AddTagPair("model", model)
	if err != nil {
		return fmt.Errorf("failed to add model tag: %w", err)
	}

	tagsSlice := reqTags.Slice()
	return c.setDefaultNodeTagsUnsafe(tagsSlice)
}

func (c *Client) GetDefaultModel() (string, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	reqTags, err := tags.FromSlice(c.params.NodeTags)
	if err != nil {
		return "", err
	}

	modelTags := reqTags.GetValues("model")
	if len(modelTags) > 1 {
		return "", fmt.Errorf("expected one or fewer model tags, got %d", len(modelTags))
	} else if len(modelTags) == 0 {
		return "", nil
	}

	return modelTags[0], nil
}

func (c *Client) GetModels(ctx context.Context) ([]string, error) {
	badge, err := c.nodeFinder.GetBadge(ctx)
	if err != nil {
		return []string{}, err
	}
	return badge.Credentials.Models, nil
}

func (c *Client) GetMaxCandidateNodes() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.maxCandidateNodes
}

// VerifiedNodeFinder finds verified nodes.
type VerifiedNodeFinder interface {
	// FindVerifiedNodes returns between 0 and maxNodes verified nodes that contain the given tags.
	FindVerifiedNodes(ctx context.Context, maxNodes int, tagslist tags.Tags) ([]VerifiedNode, error)
	ListCachedVerifiedNodes() ([]VerifiedNode, error)
	GetBadge(ctx context.Context) (credentialing.Badge, error)
	Close() error
}

type AuthClient interface {
	RemoteConfig() authclient.RemoteConfig
	GetAttestationToken(ctx context.Context) (*anonpay.BlindedCredit, error)
	GetCredit(ctx context.Context, amountNeeded int64) (*anonpay.BlindedCredit, error)
	PutCredit(ctx context.Context, finalCredit *anonpay.BlindedCredit) error
	GetBadge(ctx context.Context) (credentialing.Badge, error)
	Payee() *anonpay.Payee
}

const defaultHTTPClientTimeout = 5 * time.Minute
const defaultHTTPDialTimeout = 30 * time.Second

// HTTPClient is a convenience method. It returns a [http.Client]
// that uses this client as its transport.
func (c *Client) HTTPClient() *http.Client {
	return &http.Client{
		Timeout:   defaultHTTPClientTimeout,
		Transport: otelutil.NewTransport(c),
	}
}

func (c *Client) RoundTrip(r *http.Request) (*http.Response, error) {
	defer func() {
		// If there's no body this will panic?
		if r.Body == nil {
			return
		}
		err := r.Body.Close()
		if err != nil {
			// http.RoundTripper offers no guarantees that closing will happen synchronously,
			// so just log the error.
			slog.Error("failed to close request body", "error", err)
		}
	}()

	if r.URL.Scheme == "" {
		return nil, errors.New("tcloud: request URL needs a scheme")
	}

	// Use a shallow clone so we can modify fields.
	r = r.Clone(r.Context())

	// Ensure the request doesn't contain any server-side only fields,
	// as the bhttp encoder expect client-side only.
	r.RequestURI = ""

	host, err := validNormalizedHost(r)
	if err != nil {
		return nil, err
	}
	r.URL.Host = host
	r.Host = ""

	params, err := c.paramsForRequest(r)
	if err != nil {
		return nil, fmt.Errorf("tcloud: failed to get parameters for request: %w", err)
	}

	payment, nodes, err := c.requestResources(r.Context(), params)
	if err != nil {
		return nil, fmt.Errorf("tcloud: failed to get resources: %w", err)
	}
	defer func() {
		// cancel payment if we return due to an error.
		if err != nil {
			err = errors.Join(err, payment.Cancel())
		}
	}()

	badge, err := c.nodeFinder.GetBadge(r.Context())
	if err != nil {
		return nil, fmt.Errorf("failed to get badge: %w", err)
	}
	badgeHeader, err := encodeBadgeHeader(&badge)
	if err != nil {
		return nil, err
	}
	r.Header.Set(BadgeHeader, badgeHeader)

	resp, err := c.doRouterRequest(payment, nodes, r)
	if err != nil {
		return nil, fmt.Errorf("tcloud: %w", err)
	}

	return resp, nil
}

func (c *Client) paramsForRequest(r *http.Request) (RequestParams, error) {
	params := c.DefaultRequestParams()

	if c.requestParamsFunc != nil {
		newParams, err := c.requestParamsFunc(r, params)
		if err != nil {
			return RequestParams{}, err
		}

		c.mu.RLock()
		defer c.mu.RUnlock()
		err = c.validateCreditAmount(newParams.CreditAmount)
		if err != nil {
			return RequestParams{}, err
		}

		params = newParams
	}

	requestTags, err := tags.FromSlice(params.NodeTags)
	if err != nil {
		return RequestParams{}, err
	}
	if slices.Contains(GetPromptPaths(), r.URL.Path) && !requestTags.ContainsKey("model") {
		return RequestParams{}, errors.New("unable to send request without 'model' node tag set and no default fallback model")
	}

	return params, nil
}

func (c *Client) doRouterRequest(payment wallet.Payment, nodes []VerifiedNode, r *http.Request) (*http.Response, error) {
	if len(nodes) == 0 {
		return nil, ErrNotEnoughVerifiedNodes
	}

	ctx := r.Context()

	sealer, reqMediaType, err := messages.EncapsulateRequest(c.requestSender, r)
	if err != nil {
		return nil, fmt.Errorf("failed to encapsulate compute request: %w", err)
	}

	// Prepare request candidates and their sealers. We need a sealer for each
	// node because we don't know in advance which node will encrypt the response.
	info := api.ComputeRequestInfo{
		Candidates: make([]api.ComputeCandidate, 0, len(nodes)),
	}
	sealers := make(map[uuid.UUID]twoway.ResponseOpenerFunc, len(nodes))
	for _, node := range nodes {
		candidate, openerFunc, err := node.toCandidate(sealer)
		if err != nil {
			return nil, fmt.Errorf("failed to create candidate for node: %w", err)
		}

		info.Candidates = append(info.Candidates, candidate)
		sealers[node.Manifest.ID] = openerFunc
	}

	routingInfo, err := info.MarshalText()
	if err != nil {
		return nil, fmt.Errorf("failed to marshal compute request info to text: %w", err)
	}

	// Prepare the credit header
	creditHeader, err := encodeCreditHeader(payment.Credit())
	if err != nil {
		return nil, err
	}

	// Create the router request.
	routerReq, err := http.NewRequestWithContext(ctx, http.MethodPost, c.routerURL, sealer)
	if err != nil {
		return nil, fmt.Errorf("failed to create router request: %w", err)
	}
	if msgLen, isKnownLen := sealer.Len(); isKnownLen {
		routerReq.ContentLength = int64(msgLen)
	}

	confsecPing := r.Header.Get("X-Confsec-Ping")

	// Set routing and credit headers
	routerReq.Header.Set("Content-Type", reqMediaType)
	routerReq.Header.Set(api.RoutingInfoHeader, string(routingInfo))
	routerReq.Header.Set(ahttp.CreditHeader, creditHeader)
	if confsecPing != "" {
		routerReq.Header.Set("X-Confsec-Ping", confsecPing)
	}
	slog.InfoContext(ctx, "making request with credit", "value", payment.Credit().Value)

	// Send the request to the router.
	routerResp, err := c.anonHTTPClient.Do(routerReq)
	if err != nil {
		return nil, fmt.Errorf("failed to do client router request: %w", err)
	}

	if routerResp.StatusCode != http.StatusOK {
		return nil, RouterError{
			StatusCode: routerResp.StatusCode,
			Message:    httpfmt.ParseBodyAsError(routerResp, err).Error(),
		}
	}

	// the router response contains the refund as a trailer, refundReader
	// will process the refund when it encounters io.EOF or is closed.
	routerResp.Body = &refundReader{
		ctx:      r.Context(),
		body:     routerResp.Body,
		trailer:  routerResp.Trailer,
		refunded: false,
		payment:  payment,
	}

	defer func() {
		// if we encounter an error after this point we need to make sure
		// to close the body on the routerResp as the body won't be returned
		// to the caller.
		//
		// Since at this point the routerResp.Body is a refundReader, the Close
		// call will take care of handling any refunds.
		if err != nil {
			closeErr := routerResp.Body.Close()
			if closeErr != nil {
				err = errors.Join(err, fmt.Errorf("attempted to close router response body due to error, but it failed: %w", err))
			}
		}
	}()

	if confsecPing != "" {
		// shortcircuit when we're just pinging.
		return routerResp, nil
	}

	nodeID, err := uuidv7.Parse(routerResp.Header.Get(api.NodeIDHeader))
	if err != nil {
		return nil, fmt.Errorf("failed to parse router response %s header: %w", api.NodeIDHeader, err)
	}

	openerFunc, ok := sealers[nodeID]
	if !ok {
		return nil, fmt.Errorf("router returned response for non-candidate node %s", nodeID)
	}

	resp, err := messages.DecapsulateResponse(ctx, openerFunc, routerResp.Header.Get("Content-Type"), routerResp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to decapsulate compute response: %w", err)
	}

	// ensure that before the decapsulated response is closed,
	// the router body is also closed.
	resp.Body = &decapRespBody{
		body:             resp.Body,
		routerRespCloser: routerResp.Body,
	}

	return resp, nil
}

type refundReader struct {
	ctx      context.Context
	eof      bool
	trailer  http.Header
	body     io.ReadCloser
	refunded bool
	payment  wallet.Payment
	closed   bool
}

func (r *refundReader) Read(p []byte) (int, error) {
	n, err := r.body.Read(p)
	if err != nil && errors.Is(err, io.EOF) {
		r.eof = true
		refundErr := r.doRefund()
		if refundErr != nil {
			err = errors.Join(err, fmt.Errorf("failed to do refund: %w", refundErr))
		}
	}

	return n, err
}

func (r *refundReader) Close() error {
	if r.closed {
		return nil
	}
	r.closed = true

	var err error
	// drain the body to make sure trailers are processed.
	if !r.eof {
		_, discardErr := io.Copy(io.Discard, r.body)
		if discardErr != nil {
			err = errors.Join(err, fmt.Errorf("failed to discard remaining body: %w", discardErr))
		}
	}

	// close the body and process the refund, note both cases will always be called.
	bodyErr := r.body.Close()
	if bodyErr != nil {
		err = errors.Join(err, fmt.Errorf("failed to close router response body: %w", bodyErr))
	}
	refundErr := r.doRefund()
	if refundErr != nil {
		err = errors.Join(err, fmt.Errorf("failed to do refund: %w", refundErr))
	}

	if err != nil {
		// log here, because clients tend to ignore close errors.
		slog.Error("failed to close the router request body", "error", err)
	}

	return err
}

func (r *refundReader) doRefund() error {
	if r.refunded {
		return nil
	}
	r.refunded = true

	var (
		amount  int64
		trailer = r.trailer.Get(ahttp.RefundHeader)
		credit  *anonpay.UnblindedCredit
		err     error
	)
	if trailer != "" {
		credit, err = parseRefundHeader(trailer)
		if err != nil {
			return err
		}

		amount = credit.Value().AmountOrZero()
		slog.DebugContext(r.ctx, "refunding credit", "credit_amount", amount)
	} else {
		slog.DebugContext(r.ctx, "no refund")
	}

	// note, credit may be nil which is fine.
	err = r.payment.Success(credit)
	if err != nil {
		return err
	}

	refundCallback(r.ctx, amount)

	return nil
}

type decapRespBody struct {
	routerRespCloser io.Closer
	body             io.ReadCloser
}

func (b *decapRespBody) Read(p []byte) (int, error) {
	return b.body.Read(p)
}

func (b *decapRespBody) Close() error {
	// note: important that these are closed inside out.
	return errors.Join(
		b.body.Close(),
		b.routerRespCloser.Close(),
	)
}

func (c *Client) Close(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, c.walletCloseTimeout)
	defer cancel()
	pmErr := c.wallet.Close(ctx)

	fErr := c.nodeFinder.Close()
	return errors.Join(pmErr, fErr)
}

func (c *Client) requestResources(reqCtx context.Context, p RequestParams) (wallet.Payment, []VerifiedNode, error) {
	ctx, span := otelutil.Tracer.Start(reqCtx, "client.Client.requestResources")
	defer span.End()

	nodeTags, err := tags.FromSlice(p.NodeTags)
	if err != nil {
		return nil, nil, otelutil.Errorf(span, "invalid tags: %w", err)
	}

	ctx, cancel := context.WithCancel(reqCtx)
	defer cancel()

	type result struct {
		paymentOk bool
		payment   wallet.Payment
		nodes     []VerifiedNode
		err       error
	}

	results := make(chan result)

	// wait for payment.
	go func() {
		ctx, span := otelutil.Tracer.Start(ctx, "client.Client.requestResources.BeginPayment")
		defer span.End()

		payment, err := c.wallet.BeginPayment(ctx, p.CreditAmount)
		results <- result{
			paymentOk: err == nil,
			payment:   payment,
			err:       err,
		}
	}()

	// wait for nodes.
	go func() {
		ctx, span := otelutil.Tracer.Start(ctx, "client.Client.requestResources.FindVerifiedNodes")
		defer span.End()

		nodes, err := c.nodeFinder.FindVerifiedNodes(ctx, c.maxCandidateNodes, nodeTags)
		results <- result{
			nodes: nodes,
			err:   err,
		}
	}()

	var out result
	for i := 0; i < 2; i++ {
		result := <-results
		if result.paymentOk {
			out.paymentOk = true
			out.payment = result.payment
		}
		if len(result.nodes) != 0 {
			out.nodes = result.nodes
		}
		if result.err != nil {
			out.err = errors.Join(out.err, result.err)
		}
	}

	if out.err != nil {
		if out.paymentOk {
			out.err = errors.Join(out.err, out.payment.Cancel())
		}
		return nil, nil, otelutil.RecordError(span, out.err)
	}

	span.SetStatus(codes.Ok, "")
	return out.payment, out.nodes, out.err
}

func parseRefundHeader(refundHeader string) (*anonpay.UnblindedCredit, error) {
	creditBytes, err := base64.StdEncoding.DecodeString(refundHeader)
	if err != nil {
		return nil, fmt.Errorf("failed to base64 decode: %w", err)
	}

	creditProto := protos.Credit{}
	err = proto.Unmarshal(creditBytes, &creditProto)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal: %w", err)
	}

	credit := anonpay.UnblindedCredit{}
	err = credit.UnmarshalProto(&creditProto)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal proto: %w", err)
	}

	return &credit, nil
}

func encodeCreditHeader(credit *anonpay.BlindedCredit) (string, error) {
	creditProto, err := credit.MarshalProto()
	if err != nil {
		return "", fmt.Errorf("failed to marshal credit: %w", err)
	}
	creditBytes, err := proto.Marshal(creditProto)
	if err != nil {
		return "", fmt.Errorf("failed to marshal credit: %w", err)
	}
	creditB64 := base64.StdEncoding.EncodeToString(creditBytes)
	return creditB64, nil
}

func encodeBadgeHeader(badge *credentialing.Badge) (string, error) {
	return badge.Serialize()
}

func RoundCreditAmount(creditAmount int64) (int64, error) {
	cur, err := currency.Rounded(float64(creditAmount), 1.0)
	if err != nil {
		return 0, err
	}
	return cur.Amount()
}

func (c *Client) pingRouter(ctx context.Context, attempts int) error {
	var lastErr error

	// Create ticker with initial delay of 0 to execute immediately
	ticker := time.NewTicker(time.Millisecond)
	defer ticker.Stop()

	// TODO: use httpretry here once we use a http.Client for OHTTP. Also add support
	// for a httpretry with random wait times.
	for i := range attempts {
		// First attempt runs immediately, subsequent attempts wait for random duration.
		if i > 0 {
			waitMs, err := rand.Int(rand.Reader, big.NewInt(RetryWaitMsRange))
			waitMs.Add(waitMs, big.NewInt(MinimalRetryWaitMs))
			if err != nil {
				return fmt.Errorf("failed to generate random wait period: %w", err)
			}
			ticker.Reset(time.Millisecond * time.Duration(waitMs.Int64()))
		}

		select {
		case <-ticker.C:
			err := c.pingRouterRequest(ctx)
			if err == nil {
				// successfully pinged the router, exit.
				return nil
			}

			// Check if this is a 4xx response status error, exit early instead of retrying.
			var responseStatusErr ohttp.ResponseStatusError
			if errors.As(err, &responseStatusErr) && responseStatusErr.IsClientError() {
				return fmt.Errorf("router ping failed with client error HTTP %d (not retrying): %w", responseStatusErr.StatusCode, err)
			}

			lastErr = err
		case <-ctx.Done():
			return ctx.Err()
		}
	}

	return fmt.Errorf("failed to ping ohttp router after %d attempts. last error: %w", attempts, lastErr)
}

const MinimalRetryWaitMs = 2000
const RetryWaitMsRange = 5000

func (c *Client) pingRouterRequest(ctx context.Context) error {
	ctx, span := otelutil.Tracer.Start(ctx, "client.pingRouterRequest")
	defer span.End()

	ctx, cancel := context.WithTimeout(ctx, time.Second*5)
	defer cancel()
	pingURL := c.routerURL + "/ping"
	// TODO: remove the http.NoBody once OHTTP allows for Get requests.
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, pingURL, nil)
	if err != nil {
		return fmt.Errorf("failed to create ping request: %w", err)
	}

	resp, err := c.anonHTTPClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to do ping request: %w", err)
	}

	defer func() {
		err := resp.Body.Close()
		if err != nil {
			slog.Error("failed to close ping response body", "error", err)
		}
	}()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected ping status code: %d", resp.StatusCode)
	}

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read response body: %w", err)
	}

	if !bytes.Equal(data, []byte("pong")) {
		return fmt.Errorf("unexpected response body: %s", data[:min(len(data), 64)])
	}

	return nil
}

type TransparencyVerifier interface {
	CachedStatements() []transparency.Statement
	VerifyStatementWithProcessor(b []byte, processor transparency.PredicateProcessor, identity transparency.IdentityPolicy) (*transparency.Statement, transparency.BundleMetadata, error)
	VerifyStatementPredicate(b []byte, predicateKey string, identity transparency.IdentityPolicy) (*transparency.Statement, transparency.BundleMetadata, error)
}

func validNormalizedHost(r *http.Request) (string, error) {
	var err error
	host := r.Host
	if host == "" {
		host = r.URL.Host
	}

	// drop port number from host if there is one. Some clients include a port number in the host header by default.
	if strings.Contains(host, ":") {
		host, _, err = net.SplitHostPort(host)
		if err != nil {
			return "", fmt.Errorf("tcloud: failed to split host and port: %w", err)
		}
	}

	if host != messages.UnroutableHostname {
		return "", fmt.Errorf("tcloud: hostname must be %s, got %s", messages.UnroutableHostname, host)
	}

	return host, nil
}

func GetPromptPaths() []string {
	return []string{
		// TODO: remove /api/generate and /api/chat once we move OpenPCC to vLLM
		"/api/generate",
		"/api/chat",
		"/v1/completions",
		"/v1/chat/completions",
	}
}
