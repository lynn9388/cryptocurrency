/*
 * Copyright © 2018 Lynn <lynn9388@gmail.com>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

// Package base58 is a simple Base58Check implementation in Bitcoin.
// https://en.bitcoin.it/wiki/Base58Check_encoding
package base58

import (
	"bytes"
	"math/big"
)

// alphabet is the encoding scheme used for Bitcoin address.
var alphabet = []byte("123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz")

// Encode encodes a byte alice to Base58.
func Encode(data []byte) []byte {
	x := new(big.Int).SetBytes(data)
	var y []byte

	zero := big.NewInt(0)
	base := big.NewInt(int64(len(alphabet)))

	for x.Cmp(zero) > 0 {
		mod := new(big.Int)
		x.DivMod(x, base, mod)
		y = append(y, alphabet[mod.Int64()])
	}

	for _, i := range data {
		if i != 0 {
			break
		}
		y = append(y, alphabet[0])
	}

	for i, j := 0, len(y)-1; i < j; i, j = i+1, j-1 {
		y[i], y[j] = y[j], y[i]
	}

	return y
}

// Decode decodes a Base58-based data to byte slice.
func Decode(data []byte) []byte {
	x := big.NewInt(0)

	base := big.NewInt(int64(len(alphabet)))

	for _, b := range data {
		index := bytes.IndexByte(alphabet, b)
		x.Mul(x, base)
		x.Add(x, big.NewInt(int64(index)))
	}

	y := x.Bytes()

	for _, i := range data {
		if i != alphabet[0] {
			break
		}
		y = append([]byte{0x00}, y...)
	}

	return y
}
