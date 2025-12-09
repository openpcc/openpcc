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

package anonpay

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"

	"github.com/openpcc/openpcc/anonpay/currency"
	"github.com/openpcc/openpcc/gen/protos"
	"google.golang.org/protobuf/proto"
)

// BlindedCredit is a blinded credit in the anonpay system.
//
// It represents a certain value of Currency with a Nonce that identifies
// this BlindedCredit and a Signature which proves its validity.
type BlindedCredit struct {
	// _blinded prevents converting between UnblindedCredit and Credit
	//lint:ignore U1000 field is relevant at compile-time.
	_blinded  struct{}
	value     currency.Value
	nonce     Nonce
	signature []byte
}

func (c *BlindedCredit) Value() currency.Value {
	return c.value
}

func (c *BlindedCredit) Nonce() Nonce {
	return c.nonce
}

func (c *BlindedCredit) Signature() []byte {
	return bytes.Clone(c.signature)
}

func (c *BlindedCredit) MarshalText() ([]byte, error) {
	b, err := c.MarshalBinary()
	if err != nil {
		return nil, err
	}

	return []byte(base64.StdEncoding.EncodeToString(b)), nil
}

func (c *BlindedCredit) UnmarshalText(p []byte) error {
	b, err := base64.StdEncoding.DecodeString(string(p))
	if err != nil {
		return err
	}

	return c.UnmarshalBinary(b)
}

func (c *BlindedCredit) MarshalBinary() ([]byte, error) {
	pbc, err := c.MarshalProto()
	if err != nil {
		return nil, err
	}
	return proto.Marshal(pbc)
}

func (c *BlindedCredit) UnmarshalBinary(b []byte) error {
	pbc := &protos.Credit{}
	err := proto.Unmarshal(b, pbc)
	if err != nil {
		return err
	}
	return c.UnmarshalProto(pbc)
}

func (c *BlindedCredit) MarshalProto() (*protos.Credit, error) {
	if c == nil {
		return nil, errors.New("nil credit")
	}
	pv, err := c.Value().MarshalProto()
	if err != nil {
		return nil, err
	}
	return protos.Credit_builder{
		Value:     pv,
		Nonce:     c.Nonce().MarshalProto(),
		Signature: c.Signature(),
	}.Build(), nil
}

func (c *BlindedCredit) UnmarshalProto(credit *protos.Credit) error {
	if credit == nil {
		return errors.New("nil protobuf")
	}

	if !credit.HasSignature() {
		return errors.New("missing signature")
	}

	sig := credit.GetSignature()
	if len(sig) == 0 {
		return errors.New("zero-len signature")
	}

	val := currency.Value{}
	err := val.UnmarshalProto(credit.GetValue())
	if err != nil {
		return fmt.Errorf("failed to unmarshal value: %w", err)
	}

	nonce := Nonce{}
	err = nonce.UnmarshalProto(credit.GetNonce())
	if err != nil {
		return fmt.Errorf("failed to unmarshal nonce: %w", err)
	}

	c.value = val
	c.nonce = nonce
	c.signature = sig

	return nil
}
