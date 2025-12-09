package anonpay_test

import (
	"bytes"
	"testing"
	"time"

	"github.com/openpcc/openpcc/anonpay"
	"github.com/openpcc/openpcc/anonpay/currency"
	"github.com/openpcc/openpcc/gen/protos"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func Test_UnblindedCredit_MarshalUnmarshalProtobuf(t *testing.T) {
	newNonce := func(_ *testing.T, ts time.Time) (anonpay.Nonce, *protos.Nonce) {
		n := bytes.Repeat([]byte{'1'}, anonpay.NonceLen)
		pbn := &protos.Nonce{}
		pbn.SetNonce(n)
		pbn.SetTimestamp(timestamppb.New(ts))
		return anonpay.Nonce{
			Timestamp: ts.Unix(),
			Nonce:     n,
		}, pbn
	}

	newCurrency := func(t *testing.T, amount byte) (currency.Value, *protos.Currency) {
		c, err := currency.Exact(int64(amount))
		require.NoError(t, err)
		pbc, err := c.MarshalProto()
		require.NoError(t, err)
		return c, pbc
	}

	t.Run("ok", func(t *testing.T) {
		timestamp := time.Now().UTC().Round(0)

		nonce, pbNonce := newNonce(t, timestamp)
		curr, pbCurr := newCurrency(t, 10)

		pbc := &protos.Credit{}
		pbc.SetNonce(pbNonce)
		pbc.SetValue(pbCurr)
		pbc.SetSignature(bytes.Repeat([]byte{'a'}, 16))

		wantVal := curr
		wantNonce := nonce
		wantSig := bytes.Repeat([]byte{'a'}, 16)

		got := &anonpay.UnblindedCredit{}
		err := got.UnmarshalProto(pbc)
		require.NoError(t, err)
		require.Equal(t, got.Value(), wantVal)
		require.Equal(t, got.Nonce(), wantNonce)
		require.Equal(t, got.Signature(), wantSig)

		// check again but with non-hardcoded pb
		pbc, err = got.MarshalProto()
		require.NoError(t, err)
		err = got.UnmarshalProto(pbc)
		require.NoError(t, err)

		require.Equal(t, got.Value(), wantVal)
		require.Equal(t, got.Nonce(), wantNonce)
		require.Equal(t, got.Signature(), wantSig)
	})

	failTests := map[string]func(*protos.Credit){
		"fail, missing nonce": func(pbc *protos.Credit) {
			pbc.ClearNonce()
		},
		"fail, invalid nonce": func(pbc *protos.Credit) {
			pbc.GetNonce().SetNonce(nil)
		},
		"fail, missing value": func(pbc *protos.Credit) {
			pbc.ClearValue()
		},
		"fail, invalid value": func(pbc *protos.Credit) {
			pbc.GetValue().SetCurrency([]byte{4})
		},
		"fail, missing signature": func(pbc *protos.Credit) {
			pbc.ClearSignature()
		},
		"fail, nil signature": func(pbc *protos.Credit) {
			pbc.SetSignature(nil)
		},
		"fail, empty signature": func(pbc *protos.Credit) {
			pbc.SetSignature([]byte{})
		},
	}

	for name, tc := range failTests {
		t.Run(name, func(t *testing.T) {
			timestamp := time.Now().UTC().Round(0)

			_, pbNonce := newNonce(t, timestamp)
			_, pbCurr := newCurrency(t, 10)

			pbc := &protos.Credit{}
			pbc.SetNonce(pbNonce)
			pbc.SetValue(pbCurr)
			pbc.SetSignature(bytes.Repeat([]byte{'a'}, 16))

			tc(pbc)

			c := &anonpay.UnblindedCredit{}
			err := c.UnmarshalProto(pbc)
			require.Error(t, err)
		})
	}

	t.Run("fail, marshal nil credit", func(t *testing.T) {
		var c *anonpay.UnblindedCredit
		_, err := c.MarshalProto()
		require.Error(t, err)
	})

	t.Run("fail, unmarshal nil", func(t *testing.T) {
		c := &anonpay.UnblindedCredit{}
		err := c.UnmarshalProto(nil)
		require.Error(t, err)
	})
}
