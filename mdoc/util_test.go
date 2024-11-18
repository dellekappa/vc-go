package mdoc

import (
	"encoding/hex"
	"github.com/fxamacker/cbor/v2"
	"github.com/google/go-cmp/cmp"
	"io"
	"testing"
)

func NewDeterministicRand() io.Reader {
	return &deterministicRand{1, 2, 3, 4}
}

type deterministicRand []byte

func (r deterministicRand) Read(p []byte) (n int, err error) {
	write := len(p)
	if write == 0 {
		return 0, io.EOF
	}
	wrote := 0
	for wrote < write {
		wrote += copy(p[wrote:], r)
	}
	return wrote, nil
}

func decodeHex(t *testing.T, encoded string) []byte {
	t.Helper()

	decoded, err := hex.DecodeString(encoded)
	if err != nil {
		t.Fatal(err)
	}

	return decoded
}

func newTestUUID(t *testing.T, rand io.Reader) *UUID {
	t.Helper()
	uuid, err := NewUUID(rand)
	if err != nil {
		t.Fatal(err)
	}
	return uuid
}
func newBenchmarkUUID(b *testing.B, rand io.Reader) *UUID {
	b.Helper()
	uuid, err := NewUUID(rand)
	if err != nil {
		b.Fatal(err)
	}
	return uuid
}

func expectCBOR(t *testing.T, expected, got []byte) {
	t.Helper()

	diagExpected := diagnoseCBOR(t, expected)
	diagGot := diagnoseCBOR(t, got)

	if diff := cmp.Diff(diagExpected, diagGot); diff != "" {
		t.Fatalf("diff:\n%s\nexptected:\n%s\ngot:\n%s", diff, diagExpected, diagGot)
	}
}

func diagnoseCBOR(t *testing.T, encoded []byte) string {
	t.Helper()

	diag, err := cbor.Diagnose(encoded)
	if err != nil {
		t.Fatal(err)
	}
	return diag
}
