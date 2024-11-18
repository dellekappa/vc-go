package mdoc

type DeviceResponse struct {
	Version        string          `cbor:"version"`
	Documents      []Document      `cbor:"documents,omitempty"`
	DocumentErrors []DocumentError `cbor:"documentErrors,omitempty"`
	Status         StatusCode      `cbor:"status"`
}

type StatusCode uint

const (
	StatusCodeOK                  StatusCode = 0
	StatusCodeGeneralError        StatusCode = 10
	StatusCodeCBORDecodingError   StatusCode = 11
	StatusCodeCBORValidationError StatusCode = 12
)

func NewDeviceResponse(
	documents []Document,
	documentErrors []DocumentError,
	status StatusCode,
) *DeviceResponse {
	return &DeviceResponse{
		"1.0",
		documents,
		documentErrors,
		status,
	}
}

type DocumentError map[DocType]ErrorCode
