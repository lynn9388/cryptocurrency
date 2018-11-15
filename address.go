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
	"encoding/gob"
	"io/ioutil"
	"os"

	"github.com/lynn9388/cryptocurrency/base58"
	"go.uber.org/zap"
	"golang.org/x/crypto/ripemd160"
)

const version = byte(0x00)
const checksumLength = 4

// Wallet stores a collection of account.
type Wallet struct {
	Keys map[string]*ecdsa.PrivateKey
}

var log *zap.SugaredLogger

func init() {
	logger, _ := zap.NewDevelopment()
	log = logger.Sugar()
}

// NewWallet creates a wallet and loads data from a file if it exists.
func NewWallet(filename string) *Wallet {
	wallet := new(Wallet)
	wallet.Keys = make(map[string]*ecdsa.PrivateKey)

	if _, err := os.Stat(filename); !os.IsNotExist(err) {
		content, err := ioutil.ReadFile(filename)
		if err != nil {
			log.Panic(err)
		}

		gob.Register(elliptic.P256())
		decoder := gob.NewDecoder(bytes.NewReader(content))
		err = decoder.Decode(wallet)
		if err != nil {
			log.Panic(err)
		}
	}

	return wallet
}

// SaveToFile saves wallet to a file.
func (w *Wallet) SaveToFile(filename string) {
	var buf bytes.Buffer

	gob.Register(elliptic.P256())
	encoder := gob.NewEncoder(&buf)
	err := encoder.Encode(w)
	if err != nil {
		log.Panic(err)
	}

	err = ioutil.WriteFile(filename, buf.Bytes(), 0644)
	if err != nil {
		log.Panic(err)
	}
}

// CreateAccount creates a new account address and adds it to wallet.
func (w *Wallet) CreateAccount() string {
	key := NewKey()
	addr := string(GetAddress(&key.PublicKey))
	w.Keys[addr] = key
	return addr
}

// GetKey returns a key by its address.
func (w *Wallet) GetKey(addr string) *ecdsa.PrivateKey {
	return w.Keys[addr]
}

// GetAddresses returns all the addresses stored in the wallet.
func (w *Wallet) GetAddresses() []string {
	var addrs []string
	for addr := range w.Keys {
		addrs = append(addrs, addr)
	}
	return addrs
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
	hash := HashPubKey(pk)
	data := append([]byte{version}, hash...)
	checksum := checksum(data)
	address := append(data, checksum[:checksumLength]...)
	return base58.Encode(address)
}

// GetPubKeyHash returns the hash of public key from an address.
func GetPubKeyHash(addr []byte) []byte {
	decodedHash, err := base58.Decode(addr)
	if err != nil {
		log.Panic(err)
	}
	return decodedHash[1 : len(decodedHash)-checksumLength]
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

// HashPubKey uses RIPEMED160(SHA256(PK)) to hash public key.
func HashPubKey(pk *ecdsa.PublicKey) []byte {
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
