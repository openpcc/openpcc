package gateway

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGenerateKeyPairs_Table(t *testing.T) {
	tests := map[string]struct {
		numSeeds    int
		expErr      bool
		expectedErr string
	}{
		"success with few seeds": {
			numSeeds: 2,
			expErr:   false,
		},
		"max allowed seeds": {
			numSeeds: 255,
			expErr:   false,
		},
		"fails exceeding maximum seeds": {
			numSeeds: 256,
			expErr:   true,
		},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			seeds := make([][]byte, tt.numSeeds)
			for i := range seeds {
				seeds[i] = bytes.Repeat([]byte{byte(i)}, 32)
			}

			kps, err := generateKeyPairs(seeds)

			if tt.expErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.NotNil(t, kps)
			assert.Equal(t, tt.numSeeds, len(kps))

			// ensure unique keys
			idx := make(map[string]struct{}, len(kps))
			for i := range kps {
				pubKey, _ := kps[i].KeyConfig.PublicKey.MarshalBinary()
				require.NotContains(t, idx, string(pubKey))
				idx[string(pubKey)] = struct{}{}
			}
		})
	}
}
