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
	"fmt"
	"net/http"

	"github.com/openpcc/openpcc/transparency"
)

type scratch struct {
	authClient AuthClient
}

type Option func(c *Client, s *scratch, config *Config) error

func WithVerifiedNodeFinder(f VerifiedNodeFinder) Option {
	return func(c *Client, _ *scratch, _ *Config) error {
		c.nodeFinder = f
		return nil
	}
}

func WithWallet(w Wallet) Option {
	return func(c *Client, _ *scratch, _ *Config) error {
		c.wallet = w
		return nil
	}
}

func WithAuthClient(authClient AuthClient) Option {
	return func(_ *Client, s *scratch, _ *Config) error {
		s.authClient = authClient
		return nil
	}
}

func WithAnonHTTPClient(anonHTTPClient *http.Client) Option {
	return func(c *Client, _ *scratch, _ *Config) error {
		c.anonHTTPClient = anonHTTPClient
		return nil
	}
}

func WithNonAnonHTTPClient(httpClient *http.Client) Option {
	return func(c *Client, _ *scratch, _ *Config) error {
		c.nonAnonHTTPClient = httpClient
		return nil
	}
}

// WithRouterURL overwrites the default router url. Should really only be used in tests,
// as the full confsec environments expect a hardcoded router url of http://confsec-router.invalid
func WithRouterURL(routerURL string) Option {
	return func(c *Client, _ *scratch, _ *Config) error {
		c.routerURL = routerURL
		return nil
	}
}

func WithRouterPing(enabled bool) Option {
	return func(_ *Client, _ *scratch, config *Config) error {
		config.PingRouter = enabled
		return nil
	}
}

func WithCreditAmount(limit int64) Option {
	return func(c *Client, _ *scratch, _ *Config) error {
		c.params.CreditAmount = limit
		return nil
	}
}

func WithNodeTags(tags []string) Option {
	return func(c *Client, _ *scratch, _ *Config) error {
		c.params.NodeTags = tags
		return nil
	}
}

func WithMaxCandidateNodes(maxCandidates int) Option {
	return func(c *Client, _ *scratch, _ *Config) error {
		c.maxCandidateNodes = maxCandidates
		return nil
	}
}

func WithTransparencyOIDCIssuer(issuer string) Option {
	return func(c *Client, s *scratch, config *Config) error {
		config.TransparencyIdentityPolicy.OIDCIssuer = issuer
		return nil
	}
}

func WithTransparencyOIDCIssuerRegex(regex string) Option {
	return func(c *Client, s *scratch, config *Config) error {
		config.TransparencyIdentityPolicy.OIDCIssuerRegex = regex
		return nil
	}
}

func WithTransparencyOIDCSubject(subject string) Option {
	return func(c *Client, s *scratch, config *Config) error {
		config.TransparencyIdentityPolicy.OIDCSubject = subject
		return nil
	}
}

func WithTransparencyOIDCSubjectRegex(regex string) Option {
	return func(c *Client, s *scratch, config *Config) error {
		config.TransparencyIdentityPolicy.OIDCSubjectRegex = regex
		return nil
	}
}

func WithTransparencyEnvironment(environment string) Option {
	return func(c *Client, s *scratch, config *Config) error {
		if environment != transparency.EnvironmentProd && environment != transparency.EnvironmentStaging {
			return fmt.Errorf("invalid transparency environment: %s", environment)
		}
		config.TransparencyVerifier.Environment = transparency.Environment(environment)
		return nil
	}
}
