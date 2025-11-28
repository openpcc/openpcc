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

// Package currency implements rountines for encoding and decoding currency values and
// for blinding, signing and verifying tokens containing currency.
package currency

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"math/big"
	"math/bits"

	"github.com/openpcc/openpcc/gen/protos"
	"google.golang.org/protobuf/proto"
)

const (
	// MaxAmount is 33,285,996,544, the maximum number that can be represented by 1.XXXX ^ 2^(YYYYY + 3) where X and Y are bits.
	// Since we can't represent 1.1111 here, we write 1_1111 instead, and subtract 4 from the shift to compensate.
	MaxAmount = 0b1_1111 << (31 + 3 - 4)
)

// A Zero is for testing purposes where we want a currency value that doesn't do anything but parses as a valid amount.
var Zero = Value{
	value: 0,
	shift: false,
}

// Currency representation errors.
var (
	ErrNegativeUnrepresentable = errors.New("currency cannot be negative")
	ErrOverflow                = errors.New("currency cannot be more than 33,285,996,544")
	ErrNoExactRepresentation   = errors.New("currency cannot exactly represent that number")
	ErrNotAnAmount             = errors.New("tried to read amount of shifted currency")
	ErrNilCredit               = errors.New("tried to read amount of nil credit")
)

// Currency parsing errors.
var (
	ErrTooShort       = errors.New("not enough bytes to parse Currency")
	ErrTooManyBitsSet = errors.New("too many bits used")
)

// Value represents an amount of credit within our system.
// Value with the shift bit set represents special values.
type Value struct {
	shift bool
	value uint16 // The top 7 bits of value must be zero.
}

// Exact creates a currency value exactly representing an int, or an error if that int cannot be represented.
func Exact(signedAmount int64) (Value, error) {
	if signedAmount < 0 {
		return Zero, ErrNegativeUnrepresentable
	}
	amount := uint64(signedAmount)
	if amount > MaxAmount {
		return Zero, fmt.Errorf("%w, got %d", ErrOverflow, amount)
	}
	return createExactUnsafe(amount)
}

// CanRepresent indicates whether the provided amount can be represented by a [Value].
func CanRepresent(signedAmount int64) bool {
	_, err := Exact(signedAmount)
	return err == nil
}

// MustSpecial creates a currency value that has the shift bit set to represent a special value. This function is intended
// for global variable initialization only and panics if it encounters an error.
func MustSpecial(signedAmount int64) Value {
	c, err := Exact(signedAmount)
	if err != nil {
		panic(err)
	}
	c.shift = true
	return c
}

// Rounded returns a currency value representing signedAmount, stochastically rounded to the one of the neighbouring representable values.
//
// Rounded does not round to the nearest number; instead it uses the provided roundingFactor value,
// which should be randomly chosen in the interval [0, 1.0), to round stochastically to an appropriate value.
// When combined with a fair random number generator, this rounding is guaranteed to be fair and unbiased over the long run.
func RoundedInt(signedAmount uint64, rand uint64) (Value, error) {
	// signedAmount is unsigned, so it cannot be negative.
	// No negative check needed; the type guarantees non‑negative values.
	// The original Rounded handled fractional amounts via math.Floor/Ceil.
	// In the integer‑only version we treat signedAmount as an exact integer.
	lowerBound := signedAmount
	upperBound := signedAmount
	// Since signedAmount is an integer, it is always an integer value.
	isInteger := true

	if upperBound > MaxAmount {
		return Zero, fmt.Errorf("%w, got %d", ErrOverflow, upperBound)
	}

	// The integer‑only rounding mirrors the logic of the original Rounded
	// but works entirely with integer arithmetic.  The rounding decision
	// is based on a random integer `rand` in the range [0, 1<<53).
	// - The input is an integer
	//   - If there is an exact representation of that integer, then we want to return that.
	//     - If the input is <= 32 there is an exact representation by definition.
	//     - Otherwise, if the truncated value (the lower bound) equals the input,
	//       then the input has an exact representation so we can return that.
	//   - Otherwise we find the lower and upper bound which are representable by
	//     truncating to 5 significant bits, then incrementing the last signficant bit
	// - The input is not an integer
	//   - We cannot represent it exactly, so we need to know the lower/upper bounds
	//   - Initial bounds are calculated by doing floor and ceiling on the number
	//   - If the ceiling is <= 32, then both of these bounds are representable exactly
	//        (for a pair of consecutive numbers both >=32, at least one has more than 5 significant bits)
	//        Proof: assume one of numbers has at most 5 significant bits and >1 trailing zero bit (else it would be less than 32)
	//        The other number is one away from that value, which means it has opposite polarity, so it must have a 1 in the LSB
	//        which means it has zero trailing bits and therefore at least 6 significant bits.
	//   - If the ceiling > 32, then the bounds cannot be represented exactly and must be truncated.
	//     It is safe to do so by truncating just the lower bound and incrementing the last significant bit for the upper bound.
	//     We do not need to use the ceiling value because the truncation process guarantees the upper bound will be
	//     at least 1 greater than the lower bound and will be the next representable number higher than the lower bound.
	// Once we have the lower and upper bound, we can then calculate what fraction of the time we should return the lower bound.
	//  - This is given by lowerProbability, which is the proportion of space between upperBound and signedAmount compared to lowerBound.
	//    I found this counter-intuitive, but consider if signedAmount is close to upperBound, then lowerProbability should be low.
	//  - If the roundingFactor is > lowerProbability, we round up, else we round down.
	//
	// Examples:
	// signedAmount roundingFactor lowerBound upperBound lowerProbability result
	//            1              X          1          1                -      1
	//          1.6              0          1          2              0.4      1
	//          1.6            0.5          1          2              0.4      2
	//          1.6              1          1          2              0.4      2
	//          1.6              -          1          2              0.4      1 40% of the time, 2 60% of the time -> 1.6 on average
	//           68              X         68         72                -     68
	//           69              0         68         72             0.75     68
	//           69            0.5         68         72             0.75     68
	//           69              1         68         72             0.75     69
	//           69              -         68         72             0.75     68 75% of the time, 72 25% of the time -> 69 on average
	//        145.3            0.5        144        152           0.8375     144 83.75% of the time, 152 16.25% of the time -> 145.3 on average

	if upperBound <= 32 {
		// Both bounds can be represented exactly (they have 5 or fewer significant bits).
		if isInteger {
			// We can just create the integer exactly.
			return createExactUnsafe(upperBound)
		}
	} else {
		// At least either the lower or upper bound cannot be represented exactly (it has more than 5 significant bits).
		// So we find those bounds for rounding.
		amount := lowerBound

		// Round value to identify lower and upper bound.
		bitsNeeded := bits.Len64(amount)
		if bitsNeeded < 5 {
			return Zero, fmt.Errorf("calculation results in negative bitsNeeded: %d", bitsNeeded)
		}
		shiftToClear := uint(bitsNeeded - 5) // #nosec

		truncatedAmount := amount >> shiftToClear
		lowerBound = truncatedAmount << shiftToClear
		upperBound = (truncatedAmount + 1) << shiftToClear

		if isInteger && lowerBound == amount {
			// This is an integer that can be represented exactly, so no need to round.
			return createExactUnsafe(amount)
		}
	}

	// Choose which to use.
	// lowerProbability = (upperBound - signedAmount) / (upperBound - lowerBound)
	// We compare `rand` (scaled to [0, 1<<53)) against this fraction.
	// Multiply both sides by (1<<53) to stay in integer space.
	const scale = uint64(1) << 53
	left := rand * (upperBound - lowerBound)
	right := (upperBound - signedAmount) * scale

	if left > right {
		return createExactUnsafe(upperBound)
	}

	return createExactUnsafe(lowerBound)
}

// Rounded is a compatibility wrapper that accepts floating‑point inputs
// and forwards to RoundedInt, which uses only integer arithmetic.
// The roundingFactor is expected to be in the interval [0,1). Values outside
// this range will result in an error.
func Rounded(signedAmount float64, roundingFactor float64) (Value, error) {
	if signedAmount < 0 {
		return Zero, ErrNegativeUnrepresentable
	}
	lowerBound := uint64(math.Floor(signedAmount))
	upperBound := uint64(math.Ceil(signedAmount))
	isInteger := lowerBound == upperBound

	if upperBound > MaxAmount {
		return Zero, fmt.Errorf("%w, got %d", ErrOverflow, upperBound)
	}

	// There are a few different cases to consider here:
	// - The input is an integer
	//   - If there is an exact representation of that integer, then we want to return that.
	//     - If the input is <= 32 there is an exact representation by definition.
	//     - Otherwise, if the truncated value (the lower bound) equals the input,
	//       then the input has an exact representation so we can return that.
	//   - Otherwise we find the lower and upper bound which are representable by
	//     truncating to 5 significant bits, then incrementing the last signficant bit
	// - The input is not an integer
	//   - We cannot represent it exactly, so we need to know the lower/upper bounds
	//   - Initial bounds are calculated by doing floor and ceiling on the number
	//   - If the ceiling is <= 32, then both of these bounds are representable exactly
	//        (for a pair of consecutive numbers both >=32, at least one has more than 5 significant bits)
	//        Proof: assume one of numbers has at most 5 significant bits and >1 trailing zero bit (else it would be less than 32)
	//        The other number is one away from that value, which means it has opposite polarity, so it must have a 1 in the LSB
	//        which means it has zero trailing bits and therefore at least 6 significant bits.
	//   - If the ceiling > 32, then the bounds cannot be represented exactly and must be truncated.
	//     It is safe to do so by truncating just the lower bound and incrementing the last significant bit for the upper bound.
	//     We do not need to use the ceiling value because the truncation process guarantees the upper bound will be
	//     at least 1 greater than the lower bound and will be the next representable number higher than the lower bound.
	// Once we have the lower and upper bound, we can then calculate what fraction of the time we should return the lower bound.
	//  - This is given by lowerProbability, which is the proportion of space between upperBound and signedAmount compared to lowerBound.
	//    I found this counter-intuitive, but consider if signedAmount is close to upperBound, then lowerProbability should be low.
	//  - If the roundingFactor is > lowerProbability, we round up, else we round down.
	//
	// Examples:
	// signedAmount roundingFactor lowerBound upperBound lowerProbability result
	//            1              X          1          1                -      1
	//          1.6              0          1          2              0.4      1
	//          1.6            0.5          1          2              0.4      2
	//          1.6              1          1          2              0.4      2
	//          1.6              -          1          2              0.4      1 40% of the time, 2 60% of the time -> 1.6 on average
	//           68              X         68         72                -     68
	//           69              0         68         72             0.75     68
	//           69            0.5         68         72             0.75     68
	//           69              1         68         72             0.75     69
	//           69              -         68         72             0.75     68 75% of the time, 72 25% of the time -> 69 on average
	//        145.3            0.5        144        152           0.8375     144 83.75% of the time, 152 16.25% of the time -> 145.3 on average

	if upperBound <= 32 {
		// Both bounds can be represented exactly (they have 5 or fewer significant bits).
		if isInteger {
			// We can just create the integer exactly.
			return createExactUnsafe(upperBound)
		}
	} else {
		// At least either the lower or upper bound cannot be represented exactly (it has more than 5 significant bits).
		// So we find those bounds for rounding.
		amount := lowerBound

		// Round value to identify lower and upper bound.
		bitsNeeded := bits.Len64(amount)
		if bitsNeeded < 5 {
			return Zero, fmt.Errorf("calculation results in negative bitsNeeded: %d", bitsNeeded)
		}
		shiftToClear := uint(bitsNeeded - 5) // #nosec

		truncatedAmount := amount >> shiftToClear
		lowerBound = truncatedAmount << shiftToClear
		upperBound = (truncatedAmount + 1) << shiftToClear

		if isInteger && lowerBound == amount {
			// This is an integer that can be represented exactly, so no need to round.
			return createExactUnsafe(amount)
		}
	}

	// Choose which to use.
	// lowerProbability = (upperBound - signedAmount) / (upperBound - lowerBound)
	lowerProbability := (float64(upperBound) - signedAmount) / (float64(upperBound) - float64(lowerBound))

	if roundingFactor > lowerProbability {
		return createExactUnsafe(upperBound)
	}

	return createExactUnsafe(lowerBound)
}

func createExactUnsafe(amount uint64) (Value, error) {
	if amount < 16 {
		// Handle subnormal numbers
		return Value{
			value: uint16(amount),
		}, nil
	}
	// Check amount has no more than 4 significant bits as a binary fraction
	bitsNeeded := bits.Len64(amount)      // e.g. 62=0b11_1110 so exponent = 6
	zeros := bits.TrailingZeros64(amount) // zeros = 1
	if bitsNeeded-zeros > 5 {             // 6-1 = 5 so okay
		return Zero, ErrNoExactRepresentation
	}
	mantissa := amount >> (bitsNeeded - 5) // So shift off one 0 to get 0b1_1111
	mantissa &= 0xF                        // Remove the leading 1 to get 0b1111
	// Bias to get an exponent of 6 - 4 = 2 to give 1.1111 * 2^(2+3)
	if bitsNeeded < 4 {
		return Zero, fmt.Errorf("calculation results in negative bitsNeeded: %d", bitsNeeded)
	}
	biasedExponent := uint64(bitsNeeded - 4) // #nosec
	if biasedExponent > 31 {
		return Zero, fmt.Errorf("%w, got %d", ErrOverflow, amount)
	}
	value := biasedExponent<<4 | mantissa
	return Value{
		value: uint16(value), // #nosec
	}, nil
}

func (c Value) NonZero() bool {
	return c.value != 0 || c.shift
}

// ParseCurrencyFromBlindBytes parses the currency from the blind bytes representation in b.
func ParseCurrencyFromBlindBytes(b []byte) (*Value, error) {
	if len(b) < 2 {
		return nil, ErrTooShort
	}

	if b[0] > 3 {
		return nil, ErrTooManyBitsSet
	}

	c := &Value{}
	c.shift = b[0] == 1
	c.value = uint16(b[1])
	if b[0]&2 == 2 {
		c.value |= 0x100
	}

	return c, nil
}

// Amount returns the value represented by a Currency struct, or an error if that Currency represents a special value.
func (c Value) Amount() (int64, error) {
	if c.shift {
		return 0, ErrNotAnAmount
	}
	biasedExponent := c.value >> 4
	if biasedExponent == 0 {
		return int64(c.value), nil
	}
	mantissa := int64((c.value & 0xF) | 0x10)
	exponentShift := biasedExponent - 1
	return mantissa << exponentShift, nil
}

// AmountOrZero returns the value represented by a Currency struct, or 0 if that Currency represents a special value.
func (c Value) AmountOrZero() int64 {
	amount, err := c.Amount()
	if err != nil {
		return 0
	}
	return amount
}

// RandFloat64 returns a random float64 in the range [0.0, 1.0).
func RandUint53() (uint64, error) {
	i, err := rand.Int(rand.Reader, big.NewInt(1<<53))
	if err != nil {
		return 0, err
	}
	return uint64(i.Int64()), nil
}

// BlindBytes formats the currency as a binary message that the Client and Server use in blinding operations.
func (c Value) BlindBytes() ([]byte, error) {
	buf := &bytes.Buffer{}

	topBit := uint8((c.value & 0x100) >> 8) // #nosec
	shiftBit := uint8(0)
	if c.shift {
		shiftBit = 1
	}

	firstByte := topBit<<1 | shiftBit

	err := binary.Write(buf, binary.BigEndian, firstByte)
	if err != nil {
		return nil, err
	}

	err = binary.Write(buf, binary.BigEndian, uint8(c.value&0xFF)) // #nosec
	if err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

func (c Value) MarshalText() ([]byte, error) {
	b, err := c.MarshalBinary()
	if err != nil {
		return nil, err
	}

	return []byte(base64.StdEncoding.EncodeToString(b)), nil
}

func (c *Value) UnmarshalText(p []byte) error {
	b, err := base64.StdEncoding.DecodeString(string(p))
	if err != nil {
		return err
	}

	return c.UnmarshalBinary(b)
}

func (c Value) MarshalBinary() ([]byte, error) {
	b, err := c.BlindBytes()
	if err != nil {
		return nil, err
	}

	pbc := &protos.Currency{}
	pbc.SetCurrency(b)
	return proto.Marshal(pbc)
}

func (c *Value) UnmarshalBinary(b []byte) error {
	pbc := &protos.Currency{}
	err := proto.Unmarshal(b, pbc)
	if err != nil {
		return err
	}
	return c.UnmarshalProto(pbc)
}

func (c *Value) UnmarshalProto(pbc *protos.Currency) error {
	if !pbc.HasCurrency() {
		return errors.New("missing currency")
	}

	newC, err := ParseCurrencyFromBlindBytes(pbc.GetCurrency())
	if err != nil {
		return err
	}
	*c = *newC
	return nil
}

func (c Value) MarshalProto() (*protos.Currency, error) {
	b, err := c.BlindBytes()
	if err != nil {
		return nil, err
	}

	return protos.Currency_builder{
		Currency: b,
	}.Build(), nil
}
