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

package cryptocurrency

import (
	"bytes"
	"crypto/sha256"
	"os"
	"testing"

	"golang.org/x/crypto/ripemd160"
)

func TestNewWallet(t *testing.T) {
	filename := "wallet.dat"
	defer os.Remove(filename)

	wallet := NewWallet(filename)
	if len(wallet.GetAddresses()) != 0 {
		t.FailNow()
	}

	wallet.CreateAccount()
	wallet.SaveToFile(filename)
	newWallet := NewWallet(filename)
	if len(newWallet.GetAddresses()) != 1 {
		t.FailNow()
	}
}

func TestWallet_SaveToFile(t *testing.T) {
	filename := "wallet.dat"
	defer os.Remove(filename)

	wallet := NewWallet(filename)
	addressesNum := len(wallet.GetAddresses())
	wallet.CreateAccount()
	wallet.SaveToFile(filename)

	newWallet := NewWallet(filename)
	newAddressesNum := len(newWallet.GetAddresses())
	if newAddressesNum != addressesNum+1 {
		t.FailNow()
	}
}

func TestWallet_CreateAccount(t *testing.T) {
	filename := "wallet.dat"
	defer os.Remove(filename)

	wallet := NewWallet(filename)
	addressesNum := len(wallet.GetAddresses())
	wallet.CreateAccount()
	newAddressesNum := len(wallet.GetAddresses())
	if newAddressesNum != addressesNum+1 {
		t.FailNow()
	}
}

func TestWallet_GetKey(t *testing.T) {
	filename := "wallet.dat"
	defer os.Remove(filename)

	wallet := NewWallet(filename)
	addr := wallet.CreateAccount()
	if wallet.GetKey(addr) == nil {
		t.FailNow()
	}
}

func TestWallet_GetAddresses(t *testing.T) {
	filename := "wallet.dat"
	defer os.Remove(filename)

	wallet := NewWallet(filename)
	if len(wallet.GetAddresses()) != 0 {
		t.FailNow()
	}

	wallet.CreateAccount()
	if len(wallet.GetAddresses()) != 1 {
		t.FailNow()
	}
}

func TestNewKey(t *testing.T) {
	key1 := NewKey()
	key2 := NewKey()
	if key1.D.Cmp(key2.D) == 0 {
		t.Error("two keys are the same")
	}
}

func TestNewAddress(t *testing.T) {
	key := NewKey()
	addr := NewAddress(&key.PublicKey)
	if len(addr) != 34 {
		t.FailNow()
	}
}

func TestIsAddressValid(t *testing.T) {
	key := NewKey()
	addr := NewAddress(&key.PublicKey)
	if IsAddressValid(addr) == false {
		t.FailNow()
	}
}

func TestHashPubKey(t *testing.T) {
	key := NewKey()
	hash := HashPubKey(&key.PublicKey)
	if len(hash) != ripemd160.Size {
		t.Error("hash size is not 20")
	}
}

func TestToPubKeyHash(t *testing.T) {
	key := NewKey()
	addr := NewAddress(&key.PublicKey)
	if !bytes.Equal(ToPubKeyHash(addr), HashPubKey(&key.PublicKey)) {
		t.FailNow()
	}
}

func TestChecksum(t *testing.T) {
	checksum := checksum([]byte("lynn9388"))
	if len(checksum) != sha256.Size {
		t.Error("checksum size is not 32")
	}
}
