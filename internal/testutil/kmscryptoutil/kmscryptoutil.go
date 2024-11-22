// Package kmscryptoutil contains test utilities for tests using the kmscrypto wrappers.
package kmscryptoutil

import (
	"crypto"
	"encoding/base64"
	"testing"

	"github.com/dellekappa/kcms-go/doc/jose/jwk"
	"github.com/dellekappa/kcms-go/doc/jose/jwk/jwksupport"
	"github.com/dellekappa/kcms-go/kms"
	"github.com/dellekappa/kcms-go/secretlock/noop"
	kmsapi "github.com/dellekappa/kcms-go/spi/kms"
	suiteapi "github.com/dellekappa/kcms-go/suite/api"
	"github.com/dellekappa/kcms-go/suite/localsuite"
	"github.com/dellekappa/vc-go/legacy/mock/storage"
	"github.com/stretchr/testify/require"
)

// LocalKMSCrypto creates a kmscrypto.KMSCrypto instance that uses localkms and tinkcrypto.
func LocalKMSCrypto(t *testing.T) suiteapi.KMSCrypto {
	kc, err := LocalKMSCryptoErr()
	require.NoError(t, err)

	return kc
}

// LocalKMSCryptoErr creates a kmscrypto.KMSCrypto instance that uses localkms and tinkcrypto.
//
// This API returns an error instead of needing a testing parameter.
func LocalKMSCryptoErr() (suiteapi.KMSCrypto, error) {
	suite, err := LocalKCMSSuite()
	if err != nil {
		return nil, err
	}

	return suite.KMSCrypto()
}

// LocalKCMSSuite creates a kms+cms+crypto wrapper suite that uses localkms, localcms and tinkcrypto.
func LocalKCMSSuite() (suiteapi.Suite, error) {
	p, err := kms.NewAriesProviderWrapper(storage.NewKMSMockStoreProvider())
	if err != nil {
		return nil, err
	}

	s := storage.NewCMSMockStore()

	return localsuite.NewLocalKCMSSuite("local-lock://custom/master/key/", p, s, &noop.NoLock{})
}

// PubKeyBytesToJWK converts the given public key to a JWK.
func PubKeyBytesToJWK(t *testing.T, pubKeyBytes []byte, keyType kmsapi.KeyType) *jwk.JWK {
	pubJWK, err := jwksupport.PubKeyBytesToJWK(pubKeyBytes, keyType)
	require.NoError(t, err)

	tp, err := pubJWK.Thumbprint(crypto.SHA256)
	require.NoError(t, err)

	pubJWK.KeyID = base64.RawURLEncoding.EncodeToString(tp)

	return pubJWK
}
