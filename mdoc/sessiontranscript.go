package mdoc

import (
	"bytes"
	"errors"
	"github.com/fxamacker/cbor/v2"
)

var (
	ErrUnrecognizedHandover = errors.New("unrecognized handover")
)

type SessionTranscript struct {
	DeviceEngagementBytes *TaggedEncodedCBOR
	EReaderKeyBytes       *TaggedEncodedCBOR
	Handover              Handover
}

type intermediateSessionTranscript struct {
	_                     struct{} `cbor:",toarray"`
	DeviceEngagementBytes *TaggedEncodedCBOR
	EReaderKeyBytes       *TaggedEncodedCBOR
	Handover              cbor.RawMessage
}

func (st *SessionTranscript) MarshalCBOR() ([]byte, error) {
	var handoverBytes []byte
	var err error

	switch handover := st.Handover.(type) {
	case QRHandover:
		handoverBytes, err = cbor.Marshal(&handover)
		if err != nil {
			return nil, err
		}
	case NFCHandover:
		handoverBytes, err = cbor.Marshal(&handover)
		if err != nil {
			return nil, err
		}
	default:
		return nil, ErrUnrecognizedHandover
	}

	intermediateSessionTranscript := intermediateSessionTranscript{
		DeviceEngagementBytes: st.DeviceEngagementBytes,
		EReaderKeyBytes:       st.EReaderKeyBytes,
		Handover:              handoverBytes,
	}

	return cbor.Marshal(&intermediateSessionTranscript)
}

func (st *SessionTranscript) UnmarshalCBOR(data []byte) error {
	var err error

	var intermediateSessionTranscript intermediateSessionTranscript
	if err = cbor.Unmarshal(data, &intermediateSessionTranscript); err != nil {
		return err
	}

	{
		var qrHandover QRHandover
		if err = cbor.Unmarshal(intermediateSessionTranscript.Handover, &qrHandover); err == nil {
			st.DeviceEngagementBytes = intermediateSessionTranscript.DeviceEngagementBytes
			st.EReaderKeyBytes = intermediateSessionTranscript.EReaderKeyBytes
			st.Handover = qrHandover
			return nil
		}
	}

	{
		var nfcHandover NFCHandover
		if err = cbor.Unmarshal(intermediateSessionTranscript.Handover, &nfcHandover); err == nil {
			st.DeviceEngagementBytes = intermediateSessionTranscript.DeviceEngagementBytes
			st.EReaderKeyBytes = intermediateSessionTranscript.EReaderKeyBytes
			st.Handover = nfcHandover
			return nil
		}
	}

	return ErrUnrecognizedHandover
}

type Handover any

type QRHandover struct{}

func (qrh *QRHandover) MarshalCBOR() ([]byte, error) {
	return []byte{cborNull}, nil
}
func (qrh *QRHandover) UnmarshalCBOR(data []byte) error {
	if !bytes.Equal([]byte{cborNull}, data) {
		return errors.New("not a qr handover")
	}
	return nil
}

type NFCHandover struct {
	_               struct{} `cbor:",toarray"`
	HandoverSelect  []byte
	HandoverRequest []byte `cbor:",omitempty"`
}
