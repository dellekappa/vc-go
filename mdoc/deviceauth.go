package mdoc

import (
	"errors"
	"github.com/fxamacker/cbor/v2"
	"github.com/veraison/go-cose"
)

var (
	ErrNoDeviceAuthPresent        = errors.New("no device auth present")
	ErrMultipleDeviceAuthsPresent = errors.New("multiple device auths present")
)

type DeviceAuth struct {
	DeviceSignature *DeviceSignature `cbor:",omitempty"`
	DeviceMAC       *DeviceMAC       `cbor:",omitempty"`
}

type DeviceSignature cose.UntaggedSign1Message

func (ds *DeviceSignature) MarshalCBOR() ([]byte, error) {
	return cbor.Marshal((*cose.UntaggedSign1Message)(ds))
}
func (ds *DeviceSignature) UnmarshalCBOR(data []byte) error {
	return cbor.Unmarshal(data, (*cose.UntaggedSign1Message)(ds))
}

type DeviceMAC any // TODO type DeviceMAC cose.MAC0Message

type DeviceAuthentication struct {
	_                    struct{} `cbor:",toarray"`
	DeviceAuthentication string
	SessionTranscript    SessionTranscript
	DocType              DocType
	DeviceNameSpaceBytes TaggedEncodedCBOR
}

func NewDeviceAuthentication(
	sessionTranscript SessionTranscript,
	docType DocType,
	deviceNameSpaceBytes TaggedEncodedCBOR,
) *DeviceAuthentication {
	return &DeviceAuthentication{
		DeviceAuthentication: "DeviceAuthentication",
		SessionTranscript:    sessionTranscript,
		DocType:              docType,
		DeviceNameSpaceBytes: deviceNameSpaceBytes,
	}
}

func (da *DeviceAuth) Verify(
	deviceKey *DeviceKey,
	deviceAuthenticationBytes *TaggedEncodedCBOR,
) error {
	switch {
	case da.DeviceSignature != nil && da.DeviceMAC != nil:
		return ErrMultipleDeviceAuthsPresent

	case da.DeviceSignature != nil:
		return verifyDeviceSignature(deviceKey, da.DeviceSignature, deviceAuthenticationBytes)

	case da.DeviceMAC != nil:
		return errors.New("TODO") // TODO

	default:
		return ErrNoDeviceAuthPresent
	}
}

func verifyDeviceSignature(
	deviceKey *DeviceKey,
	deviceSignature *DeviceSignature,
	deviceAuthenticationBytes *TaggedEncodedCBOR,
) error {
	signatureAlgorithm, err := deviceSignature.Headers.Protected.Algorithm()
	if err != nil {
		return ErrMissingAlgorithmHeader
	}

	key, err := (*cose.Key)(deviceKey).PublicKey()
	if err != nil {
		return err
	}

	verifier, err := cose.NewVerifier(signatureAlgorithm, key)
	if err != nil {
		return err
	}

	return (*cose.Sign1Message)(deviceSignature).Verify(
		deviceAuthenticationBytes.TaggedValue,
		verifier,
	)
}
