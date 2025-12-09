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

// UnblindedCredit is a credit that was created by an Issuer without
// initiating the blind signing process via the Payee.
//
// An UnblindedCredit needs to be exchanged for a blinded credit before
// it can be processed further.
type UnblindedCredit struct {
	// _unblinded prevents converting between UnblindedCredit and Credit
	//lint:ignore U1000 field is relevant at compile-time.
	_unblinded struct{}
	value      currency.Value
	nonce      Nonce
	signature  []byte
}

func (c *UnblindedCredit) Value() currency.Value {
	return c.value
}

func (c *UnblindedCredit) Nonce() Nonce {
	return c.nonce
}

func (c *UnblindedCredit) Signature() []byte {
	return bytes.Clone(c.signature)
}

func (c *UnblindedCredit) MarshalText() ([]byte, error) {
	b, err := c.MarshalBinary()
	if err != nil {
		return nil, err
	}

	return []byte(base64.StdEncoding.EncodeToString(b)), nil
}

func (c *UnblindedCredit) UnmarshalText(p []byte) error {
	b, err := base64.StdEncoding.DecodeString(string(p))
	if err != nil {
		return err
	}

	return c.UnmarshalBinary(b)
}

func (c *UnblindedCredit) MarshalBinary() ([]byte, error) {
	pbc, err := c.MarshalProto()
	if err != nil {
		return nil, err
	}
	return proto.Marshal(pbc)
}

func (c *UnblindedCredit) UnmarshalBinary(b []byte) error {
	pbc := &protos.Credit{}
	err := proto.Unmarshal(b, pbc)
	if err != nil {
		return err
	}
	return c.UnmarshalProto(pbc)
}

func (c *UnblindedCredit) MarshalProto() (*protos.Credit, error) {
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

func (c *UnblindedCredit) UnmarshalProto(credit *protos.Credit) error {
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
