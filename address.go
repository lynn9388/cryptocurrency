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

// Package cryptocurrency provides a simple Bitcoin implementation.
package cryptocurrency

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"

	"github.com/lynn9388/cryptocurrency/base58"
	"go.uber.org/zap"
	"golang.org/x/crypto/ripemd160"
)

const version = byte(0x00)
const checksumLength = 4

var log *zap.SugaredLogger

func init() {
	logger, _ := zap.NewDevelopment()
	log = logger.Sugar()
}

// NewKey creates and returns a new ECDSA private key.
func NewKey() *ecdsa.PrivateKey {
	curve := elliptic.P256()
	sk, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		log.Panic(err)
	}
	return sk
}

// GetAddress returns the address from the public key.
func GetAddress(pk *ecdsa.PublicKey) []byte {
	hash := HashPublicKey(pk)
	data := append([]byte{version}, hash...)
	checksum := checksum(data)
	address := append(data, checksum[:checksumLength]...)
	return base58.Encode(address)
}

// IsAddressValid checks if address is valid.
func IsAddressValid(addr []byte) bool {
	address, err := base58.Decode(addr)
	if err != nil {
		return false
	}

	actualChecksum := address[len(address)-checksumLength:]
	data := address[:len(address)-checksumLength]
	targetChecksum := checksum(data)[:checksumLength]
	return bytes.Equal(actualChecksum, targetChecksum)
}

// HashPublicKey uses RIPEMED160(SHA256(PK)) to hash public key.
func HashPublicKey(pk *ecdsa.PublicKey) []byte {
	sha := sha256.Sum256(append(pk.X.Bytes(), pk.Y.Bytes()...))

	ripemd := ripemd160.New()
	_, err := ripemd.Write(sha[:])
	if err != nil {
		log.Panic(err)
	}

	return ripemd.Sum(nil)
}

// checksum uses SHA256(SHA256(data)) to generate a checksum for data.
func checksum(data []byte) []byte {
	hash := sha256.Sum256(data)
	hash = sha256.Sum256(hash[:])
	return hash[:]
}
