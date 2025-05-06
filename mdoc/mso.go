package mdoc

import (
	"crypto"
	"crypto/x509"
	"github.com/dellekappa/vc-go/cwt"
	cwt2 "github.com/dellekappa/vc-go/verifiable/cwt"
	"github.com/fxamacker/cbor/v2"
	"github.com/veraison/go-cose"
	"time"
)

type DigestAlgorithm string

const (
	DigestAlgorithmSHA256 DigestAlgorithm = "SHA-256"
	DigestAlgorithmSHA384 DigestAlgorithm = "SHA-384"
	DigestAlgorithmSHA512 DigestAlgorithm = "SHA-512"
)

type MobileSecurityObject struct {
	Version         string          `cbor:"version"`
	DigestAlgorithm DigestAlgorithm `cbor:"digestAlgorithm"`
	ValueDigests    ValueDigests    `cbor:"valueDigests"`
	DeviceKeyInfo   DeviceKeyInfo   `cbor:"deviceKeyInfo"`
	DocType         DocType         `cbor:"docType"`
	ValidityInfo    ValidityInfo    `cbor:"validityInfo"`
}

type ValueDigests map[NameSpace]DigestIDs
type DigestIDs map[DigestID]Digest
type DigestID uint
type Digest []byte

type DeviceKeyInfo struct {
	DeviceKey         *DeviceKey         `cbor:"deviceKey"`
	KeyAuthorizations *KeyAuthorizations `cbor:"keyAuthorizations,omitempty"`
	KeyInfo           *KeyInfo           `cbor:"keyInfo,omitempty"`
}

type KeyAuthorizations struct {
	NameSpaces   *AuthorizedNameSpaces   `cbor:"nameSpaces,omitempty"`
	DataElements *AuthorizedDataElements `cbor:"dataElements,omitempty"`
}

type AuthorizedNameSpaces []NameSpace
type AuthorizedDataElements map[NameSpace]DataElementsArray
type DataElementsArray []DataElementIdentifier

type KeyInfo map[int]any

type ValidityInfo struct {
	Signed         time.Time  `cbor:"signed"`
	ValidFrom      time.Time  `cbor:"validFrom"`
	ValidUntil     time.Time  `cbor:"validUntil"`
	ExpectedUpdate *time.Time `cbor:"expectedUpdate,omitempty"`
}

func NewMobileSecurityObject(data map[string]map[string]interface{}, validityInfo ValidityInfo, deviceKeyInfo DeviceKeyInfo, docType DocType, hash crypto.Hash) (*MobileSecurityObject, Claims, error) {
	claims, err := newClaims(data)
	if err != nil {
		return nil, nil, err
	}

	valueDigests, err := digestValues(claims, hash)
	if err != nil {
		return nil, nil, err
	}

	return &MobileSecurityObject{
		Version:         "1.0",
		DigestAlgorithm: DigestAlgorithm(hash.String()),
		ValueDigests:    valueDigests,
		DeviceKeyInfo:   deviceKeyInfo,
		DocType:         docType,
		ValidityInfo:    validityInfo,
	}, claims, nil
}

func digestValues(namespaces Claims, hash crypto.Hash) (ValueDigests, error) {
	digests := make(ValueDigests)
	for ns, values := range namespaces {
		digestIDs := make(DigestIDs)
		digests[ns] = digestIDs
		for i := range values {
			v := values[i]

			hashed, err := digestValue(v, hash)
			if err != nil {
				return nil, err
			}

			digestIDs[DigestID(v.DigestID)] = hashed
		}
	}

	return digests, nil
}

func digestValue(v Claim, hash crypto.Hash) ([]byte, error) {
	untaggedCbor, err := cbor.Marshal(v)
	if err != nil {
		return nil, err
	}

	taggedCbor, err := NewTaggedEncodedCBOR(untaggedCbor)
	if err != nil {
		return nil, err
	}

	digester := hash.New()
	digester.Write(taggedCbor.TaggedValue)
	hashed := digester.Sum(nil)
	return hashed, nil
}

func SignMobileSecurityObject(mso *MobileSecurityObject, signatureAlg cose.Algorithm, signer cwt.ProofCreator, certs []*x509.Certificate) (*cose.UntaggedSign1Message, error) {

	headers := cose.Headers{
		Protected:   cose.ProtectedHeader{},
		Unprotected: cose.UnprotectedHeader{},
	}

	headers.Protected.SetAlgorithm(signatureAlg)

	err := setX509Chain(headers.Unprotected, certs)
	if err != nil {
		return nil, err
	}

	encodedMso, err := encodeModeTaggedEncodedCBOR.Marshal(mso)

	//encodedMso, err := cbor.Marshal(cbor.Tag{
	//	Number:  cborTagEncodedCBOR,
	//	Content: &mso,
	//})

	if err != nil {
		return nil, err
	}

	taggedEncodedMso, err := NewTaggedEncodedCBOR(encodedMso)
	if err != nil {
		return nil, err
	}

	//taggedEncodedMso, err := encodeModeTaggedEncodedCBOR.Marshal(bstr(encodedMso))
	//
	//if err != nil {
	//	return Document{}, err
	//}

	msg := &cose.UntaggedSign1Message{
		Headers: headers,
		Payload: taggedEncodedMso.TaggedValue,
		//Payload: encodedMso,
	}

	signData, err := cwt2.GetProofValue((*cose.Sign1Message)(msg))
	if err != nil {
		return nil, err
	}

	signed, err := signer.SignCWT(cwt.SignParameters{
		CWTAlg: signatureAlg,
	}, signData)
	if err != nil {
		return nil, err
	}

	msg.Signature = signed

	return msg, nil
}

//func VerifyMobileSecurityObject(message *cose.UntaggedSign1Message, verifier cwt.ProofChecker) error {
//
//	var msg []byte
//	var signature []byte
//
//	algo, err := message.Headers.Protected.Algorithm()
//	if err != nil {
//		return err
//	}
//
//	x509Chain, err := getX509Chain(message.Headers.Unprotected)
//	if err != nil {
//		return err
//	}
//
//	// currently supported only COSE_Key, x5chain is not supported by go opensource implementation yet
//	//keyMaterial, _ := message.Headers.Protected[proof.COSEKeyHeader].(string)   // nolint
//	//keyIDBinary, _ := message.Headers.Protected[cose.HeaderLabelKeyID].([]byte) // nolint
//	//
//	//var rawKeyID string
//	//if len(keyIDBinary) > 0 {
//	//	rawKeyID = string(keyIDBinary)
//	//}
//
//	//var expectedProofIssuer string
//	//if v.expectedProofIssuer != nil {
//	//	expectedProofIssuer = *v.expectedProofIssuer
//	//}
//	//
//	//if expectedProofIssuer == "" && rawKeyID != "" {
//	//	expectedProofIssuer = strings.Split(rawKeyID, "#")[0]
//	//}
//
//	return verifier.CheckCWTProof(checker.CheckCWTProofRequest{
//		KeyMaterial: keyMaterial,
//		KeyID:       rawKeyID,
//		Algo:        algo,
//	}, expectedProofIssuer, msg, signature)
//}
