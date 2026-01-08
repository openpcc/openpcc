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

package gateway

import (
	"context"
	"fmt"
	"math"
	"time"

	"github.com/cloudflare/circl/hpke"
	"github.com/openpcc/ohttp"
	"github.com/openpcc/openpcc/keyrotation"
	"github.com/openpcc/twoway"
)

var Suite = hpke.NewSuite(hpke.KEM_X25519_KYBER768_DRAFT00, hpke.KDF_HKDF_SHA256, hpke.AEAD_AES128GCM)

func KeyConfigsForPublicKeys(pubKeys [][]byte) (ohttp.KeyConfigs, error) {
	kemID, kdfID, aeadID := Suite.Params()
	if len(pubKeys) > math.MaxUint8 {
		return nil, fmt.Errorf("can only assign id's to %d public keys, got %d", math.MaxUint8, len(pubKeys))
	}

	configs := make(ohttp.KeyConfigs, 0, len(pubKeys))
	for i, b := range pubKeys {
		pubKey, err := kemID.Scheme().UnmarshalBinaryPublicKey(b)
		if err != nil {
			return nil, fmt.Errorf("failed to unmarshal binary public key %d: %w", i, err)
		}

		configs = append(configs, ohttp.KeyConfig{
			KeyID:     byte(i),
			KemID:     kemID,
			PublicKey: pubKey,
			SymmetricAlgorithms: []ohttp.SymmetricAlgorithm{
				{
					KDFID:  kdfID,
					AEADID: aeadID,
				},
			},
		})
	}

	return configs, nil
}

func GenerateKeyConfigs(seeds [][]byte) (ohttp.KeyConfigs, error) {
	kps, err := generateKeyPairs(seeds)
	if err != nil {
		return nil, err
	}

	configs := make(ohttp.KeyConfigs, 0, len(kps))
	for _, kp := range kps {
		configs = append(configs, kp.KeyConfig)
	}

	return configs, nil
}

// KeyRotationPeriodWithID is a key rotation period with an associated OHTTP key ID.
// This is specific to the OHTTP package, but not part of our OSS Release, so it's kept here.
type KeyRotationPeriodWithID struct {
	keyrotation.Period

	// KeyID is the ID of the key this rotation metadata applies to.
	KeyID byte `json:"key_id"`
}

// ExpiringKeyPair is an ohttp keypair with an associated keyrotation Period
type ExpiringKeyPair struct {
	ohttp.KeyPair
	keyrotation.Period
}

func (k ExpiringKeyPair) FindSecretKey(ctx context.Context, header twoway.RequestHeader) (ohttp.SecretKeyInfo, error) {
	keyInfo, err := k.KeyPair.FindSecretKey(ctx, header)
	if err != nil {
		return ohttp.SecretKeyInfo{}, err
	}

	err = k.CheckIfActive()
	if err != nil {
		return ohttp.SecretKeyInfo{}, err
	}

	return keyInfo, nil
}

type KeyPairs []ExpiringKeyPair

func (kps KeyPairs) FindSecretKey(ctx context.Context, header twoway.RequestHeader) (ohttp.SecretKeyInfo, error) {
	var lastErr error
	for _, kp := range kps {
		info, err := kp.FindSecretKey(ctx, header)
		if err != nil {
			lastErr = err
			continue
		}

		return info, nil
	}

	return ohttp.SecretKeyInfo{}, lastErr
}

func generateKeyPairs(seeds [][]byte) (KeyPairs, error) {
	if len(seeds) > math.MaxUint8 {
		return nil, fmt.Errorf("can at most generate %d keypairs, got %d seeds", math.MaxUint8, len(seeds))
	}

	kps := make(KeyPairs, 0, len(seeds))
	for i := range seeds {
		kps = append(kps, generateKeyPair(byte(i), seeds[i], time.Now(), time.Now().AddDate(1, 0, 0)))
	}

	return kps, nil
}

func generateKeyPair(id byte, seed []byte, activeFrom, activeUntil time.Time) ExpiringKeyPair {
	kemID, kdfID, aeadID := Suite.Params()
	pubKey, secretKey := kemID.Scheme().DeriveKeyPair(seed)

	return ExpiringKeyPair{
		KeyPair: ohttp.KeyPair{
			SecretKey: secretKey,
			KeyConfig: ohttp.KeyConfig{
				KeyID:     id,
				KemID:     kemID,
				PublicKey: pubKey,
				SymmetricAlgorithms: []ohttp.SymmetricAlgorithm{
					{
						KDFID:  kdfID,
						AEADID: aeadID,
					},
				},
			},
		},
		Period: keyrotation.Period{
			ActiveFrom:  activeFrom,
			ActiveUntil: activeUntil,
		},
	}
}
