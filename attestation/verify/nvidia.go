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

package verify

import (
	"crypto/ecdsa"
	"crypto/x509"
	_ "embed"
	"errors"
	"fmt"
	"log/slog"

	"github.com/golang-jwt/jwt/v5"
)

var (
	//go:embed nras_root.pem
	NRASRootCert []byte
)

type AttestationVerifier interface {
	VerifyJWT(signedToken string) (*jwt.Token, error)
}

type NRASVerifier struct {
	intermediateCert *x509.Certificate
}

func NewNRASVerifier(intermediateCert *x509.Certificate) *NRASVerifier {
	return &NRASVerifier{
		intermediateCert: intermediateCert,
	}
}

func (v *NRASVerifier) VerifyJWT(signedToken string) (*jwt.Token, error) {
	publicKey, ok := v.intermediateCert.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return nil, errors.New("failed to get public key from intermediate certificate")
	}

	// parse JWT token with claims validation disabled
	parsed, err := jwt.Parse(signedToken, func(_ *jwt.Token) (any, error) {
		return publicKey, nil
	}, jwt.WithoutClaimsValidation(), jwt.WithValidMethods([]string{"ES384"}))
	if parsed != nil && parsed.Claims != nil {
		if c, ok := parsed.Claims.(jwt.MapClaims); ok {
			slog.Info("NRAS JWT", "nbf", c["nbf"], "exp", c["exp"], "err", err)
		}
	}
	if err != nil {
		return nil, fmt.Errorf("failed to parse the JWT: %w", err)
	}

	return parsed, nil
}
