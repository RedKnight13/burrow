// SPDX-License-Identifier: Apache-2.0

package fabricx

import (
	"bytes"
	"testing"
)

func TestMarshalExecuteResponseRoundTrip(t *testing.T) {
	in := &ExecuteResponse{
		ReadWriteSet: []byte{0x01, 0x02},
		Status:       StatusRejected,
		Message:      "ethereum transaction is empty",
	}
	first, err := MarshalExecuteResponse(in)
	if err != nil {
		t.Fatalf("MarshalExecuteResponse: %v", err)
	}
	second, err := MarshalExecuteResponse(in)
	if err != nil {
		t.Fatalf("MarshalExecuteResponse again: %v", err)
	}
	if !bytes.Equal(first, second) {
		t.Fatalf("encoding is not stable: %x vs %x", first, second)
	}
	if !bytes.Contains(first, []byte{0x0a}) || !bytes.Contains(first, []byte{0x18, 0x04}) || !bytes.Contains(first, []byte{0x22}) {
		t.Fatalf("missing field tags in %x", first)
	}
	out, err := UnmarshalExecuteResponse(first)
	if err != nil {
		t.Fatalf("UnmarshalExecuteResponse: %v", err)
	}
	if out.Status != in.Status || out.Message != in.Message || !bytes.Equal(out.ReadWriteSet, in.ReadWriteSet) {
		t.Fatalf("round trip = %+v, want %+v", out, in)
	}
}
