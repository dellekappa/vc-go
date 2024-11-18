package mdoc

import (
	"fmt"
	"github.com/fxamacker/cbor/v2"
	"github.com/veraison/go-cose"
)

type Document struct {
	DocType      DocType       `cbor:"docType"`
	IssuerSigned IssuerSigned  `cbor:"issuerSigned"`
	DeviceSigned *DeviceSigned `cbor:"deviceSigned,omitempty"`
	Errors       Errors        `cbor:"errors,omitempty"`
}

type IssuerSigned struct {
	NameSpaces IssuerNameSpaces `cbor:"nameSpaces,omitempty"`
	IssuerAuth IssuerAuth       `cbor:"issuerAuth"`
}

type IssuerNameSpaces map[NameSpace]IssuerSignedItemBytes
type IssuerSignedItemBytes []TaggedEncodedCBOR

func (ins IssuerNameSpaces) Claims() (Claims, error) {
	namespacedClaims := make(Claims)
	for nameSpace, issuerSignedItems := range ins {
		claims := make([]Claim, len(issuerSignedItems))
		for i, issuerSignedItem := range issuerSignedItems {
			var claim Claim
			if err := cbor.Unmarshal(issuerSignedItem.UntaggedValue, &claim); err != nil {
				return nil, err
			}

			claims[i] = claim
		}
		namespacedClaims[nameSpace] = claims
	}
	return namespacedClaims, nil
}

type DeviceSigned struct {
	NameSpacesBytes TaggedEncodedCBOR `cbor:"nameSpaces"`
	DeviceAuth      DeviceAuth        `cbor:"deviceAuth"`
}

func (ds *DeviceSigned) NameSpaces() (*DeviceNameSpaces, error) {
	deviceNameSpaces := new(DeviceNameSpaces)
	if err := cbor.Unmarshal(ds.NameSpacesBytes.UntaggedValue, deviceNameSpaces); err != nil {
		return nil, err
	}

	return deviceNameSpaces, nil
}

func (ds *DeviceSigned) DeviceAuthenticationBytes(docType DocType, sessionTranscript []byte) ([]byte, error) {
	deviceAuthentication := []interface{}{
		"DeviceAuthentication",
		cbor.RawMessage(sessionTranscript),
		docType,
		cbor.Tag{Number: 24, Content: ds.NameSpaces},
	}
	da, err := cbor.Marshal(deviceAuthentication)
	if err != nil {
		return nil, fmt.Errorf("error encoding transcript: %v", err)
	}
	deviceAuthenticationByte, err := cbor.Marshal(cbor.Tag{Number: 24, Content: da})
	if err != nil {
		return nil, fmt.Errorf("failed to Marshal cbor %w", err)
	}
	return deviceAuthenticationByte, nil
}

type DeviceNameSpaces map[NameSpace]DeviceSignedItems
type DeviceSignedItems map[DataElementIdentifier]DataElementValue

type Errors map[NameSpace]ErrorItems
type ErrorItems map[DataElementIdentifier]ErrorCode
type ErrorCode int

func NewDocument(docType DocType, signed *cose.UntaggedSign1Message, claims Claims) (Document, error) {

	encodedNamespaces := make(IssuerNameSpaces)
	for ns, values := range claims {
		encodedItems := make(IssuerSignedItemBytes, len(values))
		for i, v := range values {
			encodedItem, err := encodeModeTaggedEncodedCBOR.Marshal(&v)
			//encodedItem, err := cbor.Marshal(&v)
			if err != nil {
				return Document{}, err
			}
			taggedEncodedItem, err := NewTaggedEncodedCBOR(encodedItem)
			if err != nil {
				return Document{}, err
			}
			encodedItems[i] = *taggedEncodedItem
		}
		encodedNamespaces[ns] = encodedItems
	}

	return Document{
		DocType: docType,
		IssuerSigned: IssuerSigned{
			NameSpaces: encodedNamespaces,
			IssuerAuth: IssuerAuth(*signed),
		},
	}, nil
}
