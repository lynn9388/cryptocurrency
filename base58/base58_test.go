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

package base58

import (
	"bytes"
	"testing"
)

func TestEncode(t *testing.T) {
	encoded := Encode([]byte("lynn9388"))
	if string(encoded) != "K9LYdys2U8F" {
		t.FailNow()
	}
}

func TestDecode(t *testing.T) {
	test := []byte("lynn9388")
	encoded := Encode(test)
	decoded, err := Decode(encoded)
	if err != nil {
		t.Error(err)
	}

	if !bytes.Equal(test, decoded) {
		t.FailNow()
	}

	tests := []string{"0", "O", "I", "l", "+", "/"}
	for _, invalidTest := range tests {
		decoded, err = Decode([]byte(invalidTest))
		if err == nil {
			t.Errorf("failed to test invalid data: %v", []byte(invalidTest))
		}
	}
}
