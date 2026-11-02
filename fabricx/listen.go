// SPDX-License-Identifier: Apache-2.0

package fabricx

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
)

const maxFrame = 1 << 20

// Serve accepts gateway connections until ctx is cancelled. Each connection
// carries one length-prefixed execute request and one length-prefixed response.
func Serve(ctx context.Context, ln net.Listener, e *Endorser) error {
	if e == nil {
		return fmt.Errorf("serve endorser: nil")
	}
	go func() {
		<-ctx.Done()
		_ = ln.Close()
	}()
	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return fmt.Errorf("serve endorser: %w", err)
		}
		err = serveOne(ctx, conn, e)
		_ = conn.Close()
		if err != nil && ctx.Err() == nil {
			return err
		}
	}
}

func serveOne(ctx context.Context, conn net.Conn, e *Endorser) error {
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}
	body, err := readFrame(conn)
	if err != nil {
		return fmt.Errorf("serve endorser: %w", err)
	}
	req, err := unmarshalExecuteRequest(body)
	if err != nil {
		return fmt.Errorf("serve endorser: %w", err)
	}
	resp, err := e.Execute(ctx, req)
	if err != nil {
		return err
	}
	out, err := MarshalExecuteResponse(resp)
	if err != nil {
		return err
	}
	if err := writeFrame(conn, out); err != nil {
		return fmt.Errorf("serve endorser: %w", err)
	}
	return nil
}

// Call dials an endorser and returns the application result.
func Call(ctx context.Context, addr string, req *ExecuteRequest) (*ExecuteResponse, error) {
	var d net.Dialer
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("call endorser: %w", err)
	}
	defer conn.Close()
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}
	body, err := marshalExecuteRequest(req)
	if err != nil {
		return nil, err
	}
	if err := writeFrame(conn, body); err != nil {
		return nil, fmt.Errorf("call endorser: %w", err)
	}
	out, err := readFrame(conn)
	if err != nil {
		return nil, fmt.Errorf("call endorser: %w", err)
	}
	resp, err := UnmarshalExecuteResponse(out)
	if err != nil {
		return nil, fmt.Errorf("call endorser: %w", err)
	}
	return resp, nil
}

func marshalExecuteRequest(req *ExecuteRequest) ([]byte, error) {
	if req == nil {
		return nil, fmt.Errorf("marshal execute request: nil")
	}
	var b []byte
	if len(req.EthereumTx) > 0 {
		b = appendLengthDelimited(b, 1, req.EthereumTx)
	}
	if req.Timestamp != 0 {
		b = appendVarintField(b, 4, uint64(req.Timestamp))
	}
	return b, nil
}

func unmarshalExecuteRequest(b []byte) (*ExecuteRequest, error) {
	out := &ExecuteRequest{}
	for len(b) > 0 {
		key, n := decodeVarint(b)
		if n <= 0 {
			return nil, fmt.Errorf("unmarshal execute request: bad key")
		}
		b = b[n:]
		field, wire := int(key>>3), int(key&7)
		switch wire {
		case 0:
			v, m := decodeVarint(b)
			if m <= 0 {
				return nil, fmt.Errorf("unmarshal execute request: bad varint")
			}
			b = b[m:]
			if field == 4 {
				out.Timestamp = int64(v)
			}
		case 2:
			ln, m := decodeVarint(b)
			if m <= 0 {
				return nil, fmt.Errorf("unmarshal execute request: bad length")
			}
			b = b[m:]
			if uint64(len(b)) < ln {
				return nil, fmt.Errorf("unmarshal execute request: short field %d", field)
			}
			val := append([]byte(nil), b[:ln]...)
			b = b[ln:]
			if field == 1 {
				out.EthereumTx = val
			}
		default:
			return nil, fmt.Errorf("unmarshal execute request: unsupported wire type %d", wire)
		}
	}
	return out, nil
}

func writeFrame(w io.Writer, body []byte) error {
	if len(body) > maxFrame {
		return fmt.Errorf("frame exceeds %d bytes", maxFrame)
	}
	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], uint32(len(body)))
	if _, err := w.Write(hdr[:]); err != nil {
		return err
	}
	_, err := w.Write(body)
	return err
}

func readFrame(r io.Reader) ([]byte, error) {
	var hdr [4]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, err
	}
	n := binary.BigEndian.Uint32(hdr[:])
	if n > maxFrame {
		return nil, fmt.Errorf("frame exceeds %d bytes", maxFrame)
	}
	body := make([]byte, n)
	if _, err := io.ReadFull(r, body); err != nil {
		return nil, err
	}
	return body, nil
}
