package mdoc

import (
	"errors"
	"io"
)

var (
	ErrInvalidUUID = errors.New("mdoc: invalid UUID")
)

type UUID [128 / 8]byte

func NewUUID(rand io.Reader) (*UUID, error) {
	var uuid UUID
	n, err := rand.Read(uuid[:])
	if n != 128/8 {
		return nil, err
	}
	return &uuid, nil
}

func UUIDFromBytes(b []byte) (*UUID, error) {
	if len(b) != 128/8 {
		return nil, ErrInvalidUUID
	}
	var uuid UUID
	copy(uuid[:], b)
	return &uuid, nil
}
