package mdoc

import "github.com/fxamacker/cbor/v2"

type DeviceRequest struct {
	Version     string       `cbor:"version"`
	DocRequests []DocRequest `cbor:"docRequests"`
}

func NewDeviceRequest(docRequests []DocRequest) *DeviceRequest {
	return &DeviceRequest{
		"1.0",
		docRequests,
	}
}

type DocRequest struct {
	ItemsRequestBytes TaggedEncodedCBOR `cbor:"itemsRequest"`
	ReaderAuth        ReaderAuth        `cbor:"readerAuth"`
}

func (dr *DocRequest) ItemsRequest() (*ItemsRequest, error) {
	itemsRequest := new(ItemsRequest)
	if err := cbor.Unmarshal(dr.ItemsRequestBytes.UntaggedValue, itemsRequest); err != nil {
		return nil, err
	}

	return itemsRequest, nil
}

type ItemsRequest struct {
	DocType     DocType        `cbor:"docType"`
	NameSpaces  NameSpaces     `cbor:"nameSpaces"`
	RequestInfo map[string]any `cbor:"requestInfo"`
}

type NameSpaces map[NameSpace]DataElements
type DataElements map[DataElementIdentifier]IntentToRetain
type IntentToRetain bool

type DocType string
type NameSpace string
type DataElementIdentifier string
type DataElementValue any
