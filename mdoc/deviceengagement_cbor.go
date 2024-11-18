package mdoc

import "github.com/fxamacker/cbor/v2"

type intermediateDeviceRetrievalMethod struct {
	_                struct{} `cbor:",toarray"`
	Type             DeviceRetrievalMethodType
	Version          uint
	RetrievalOptions cbor.RawMessage
}

func (drm *DeviceRetrievalMethod) MarshalCBOR() ([]byte, error) {
	var err error

	var retrievalOptionsBytes []byte
	switch retrievalOptions := drm.RetrievalOptions.(type) {
	case WifiOptions:
		retrievalOptionsBytes, err = cbor.Marshal(&retrievalOptions)
		if err != nil {
			return nil, err
		}

	case BLEOptions:
		retrievalOptionsBytes, err = cbor.Marshal(&retrievalOptions)
		if err != nil {
			return nil, err
		}

	case NFCOptions:
		retrievalOptionsBytes, err = cbor.Marshal(&retrievalOptions)
		if err != nil {
			return nil, err
		}

	default:
		return nil, ErrUnrecognisedRetrievalMethod
	}

	intermediateDeviceRetrievalMethod := intermediateDeviceRetrievalMethod{
		Type:             drm.Type,
		Version:          drm.Version,
		RetrievalOptions: retrievalOptionsBytes,
	}
	return cbor.Marshal(&intermediateDeviceRetrievalMethod)
}

func (drm *DeviceRetrievalMethod) UnmarshalCBOR(data []byte) error {
	var err error

	var intermediateDeviceRetrievalMethod intermediateDeviceRetrievalMethod
	if err = cbor.Unmarshal(data, &intermediateDeviceRetrievalMethod); err != nil {
		return err
	}

	var retrievalOptions RetrievalOptions
	switch intermediateDeviceRetrievalMethod.Type {
	case DeviceRetrievalMethodTypeWiFiAware:
		var wifiOptions WifiOptions
		if err = cbor.Unmarshal(intermediateDeviceRetrievalMethod.RetrievalOptions, &wifiOptions); err != nil {
			return err
		}
		retrievalOptions = wifiOptions

	case DeviceRetrievalMethodTypeBLE:
		var bleOptions BLEOptions
		if err = cbor.Unmarshal(intermediateDeviceRetrievalMethod.RetrievalOptions, &bleOptions); err != nil {
			return err
		}
		retrievalOptions = bleOptions

	case DeviceRetrievalMethodTypeNFC:
		var nfcOptions NFCOptions
		if err = cbor.Unmarshal(intermediateDeviceRetrievalMethod.RetrievalOptions, &nfcOptions); err != nil {
			return err
		}
		retrievalOptions = nfcOptions

	default:
		return ErrUnrecognisedRetrievalMethod
	}

	drm.Type = intermediateDeviceRetrievalMethod.Type
	drm.Version = intermediateDeviceRetrievalMethod.Version
	drm.RetrievalOptions = retrievalOptions

	return nil
}
