package mdoc

import (
	"errors"
	"github.com/fxamacker/cbor/v2"
)

var (
	ErrUnrecognisedRetrievalMethod = errors.New("mdoc: unrecognized retrieval method")
)

type DeviceEngagement struct {
	Version                string                  `cbor:"0,keyasint"`
	Security               Security                `cbor:"1,keyasint"`
	DeviceRetrievalMethods []DeviceRetrievalMethod `cbor:"2,keyasint,omitempty"`
	ServerRetrievalMethods []any                   `cbor:"3,keyasint,omitempty"` // TODO
	ProtocolInfo           any                     `cbor:"4,keyasint,omitempty"` // TODO
}

func NewDeviceEngagementBLE(EDeviceKey *DeviceKey, centralClientUUID, peripheralServerUUID *UUID) (*DeviceEngagement, error) {
	var eDeviceKeyBytes *TaggedEncodedCBOR
	{
		eDeviceKeyBytesUntagged, err := cbor.Marshal(EDeviceKey)
		if err != nil {
			return nil, err
		}

		eDeviceKeyBytes, err = NewTaggedEncodedCBOR(eDeviceKeyBytesUntagged)
		if err != nil {
			return nil, err
		}
	}

	return &DeviceEngagement{
		"1.0",
		Security{
			CipherSuiteIdentifier: CipherSuiteVersion,
			EDeviceKeyBytes:       *eDeviceKeyBytes,
		},
		[]DeviceRetrievalMethod{
			{
				Type:    DeviceRetrievalMethodTypeBLE,
				Version: 1,
				RetrievalOptions: BLEOptions{
					SupportsCentralClient:    centralClientUUID != nil,
					CentralClientUUID:        centralClientUUID,
					SupportsPeripheralServer: peripheralServerUUID != nil,
					PeripheralServerUUID:     peripheralServerUUID,
				},
			},
		},
		nil,
		nil,
	}, nil
}

func (de *DeviceEngagement) EDeviceKey() (*DeviceKey, error) {
	eDeviceKey := new(DeviceKey)
	if err := cbor.Unmarshal(de.Security.EDeviceKeyBytes.UntaggedValue, eDeviceKey); err != nil {
		return nil, err
	}

	return eDeviceKey, nil
}

type Security struct {
	_                     struct{} `cbor:",toarray"`
	CipherSuiteIdentifier int
	EDeviceKeyBytes       TaggedEncodedCBOR
}

type DeviceRetrievalMethodType uint

const (
	DeviceRetrievalMethodTypeNFC       DeviceRetrievalMethodType = 1
	DeviceRetrievalMethodTypeBLE       DeviceRetrievalMethodType = 2
	DeviceRetrievalMethodTypeWiFiAware DeviceRetrievalMethodType = 3
)

type DeviceRetrievalMethod struct {
	Type             DeviceRetrievalMethodType
	Version          uint
	RetrievalOptions RetrievalOptions
}

type RetrievalOptions any

type WifiOptions struct {
	PassPhraseInfoPassPhrase  string `cbor:"0,keyasint,omitempty"`
	ChannelInfoOperatingClass uint   `cbor:"1,keyasint,omitempty"`
	ChannelInfoChannelNumber  uint   `cbor:"2,keyasint,omitempty"`
	BandInfoSupportedBands    []byte `cbor:"3,keyasint,omitempty"`
}

type BLEAddress [6]byte

type BLEOptions struct {
	SupportsPeripheralServer      bool        `cbor:"0,keyasint"`
	SupportsCentralClient         bool        `cbor:"1,keyasint"`
	PeripheralServerUUID          *UUID       `cbor:"10,keyasint,omitempty"`
	CentralClientUUID             *UUID       `cbor:"11,keyasint,omitempty"`
	PeripheralServerDeviceAddress *BLEAddress `cbor:"20,keyasint,omitempty"`
}

type NFCOptions struct {
	MaxLengthCommandData  uint `cbor:"0,keyasint"`
	MaxLengthResponseData uint `cbor:"1,keyasint"`
}
