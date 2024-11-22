/*
Copyright Gen Digital Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package pubkey

import (
	"github.com/dellekappa/kcms-go/doc/jose/jwk"
	"github.com/dellekappa/kcms-go/spi/kms"
)

// BytesKey contains bytes of public key.
type BytesKey struct {
	Bytes []byte
}

// PublicKey contains a result of public key resolution.
type PublicKey struct {
	Type kms.KeyType

	BytesKey *BytesKey
	JWK      *jwk.JWK
}
