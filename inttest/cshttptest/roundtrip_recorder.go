// Copyright 2025 Nonvolatile Inc. d/b/a Confident Security

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at

//     https://www.apache.org/licenses/LICENSE-2.0

// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package cshttptest

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"net/url"
	"sort"
	"sync"
	"time"
)

type RoundTripRecorder struct {
	mu         *sync.RWMutex
	transport  *http.Transport
	recordings []RoundTripRecording
}

func NewRoundTripRecorder(transport *http.Transport) *RoundTripRecorder {
	clone := transport.Clone()
	// Force a new TCP connection per roundtrip so we can
	// record individual requests/responses.
	clone.DisableKeepAlives = true

	rr := &RoundTripRecorder{
		mu:        &sync.RWMutex{},
		transport: clone,
	}

	rr.transport.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		conn, err := transport.DialContext(ctx, network, addr)
		if err != nil {
			return nil, err
		}

		rec, ok := roundTripRecordingFromContext(ctx)
		if !ok {
			return nil, errors.New("missing roundtrip meta in context")
		}
		return rr.beginRecording(rec, conn), nil
	}

	// DialTLSContext is used for HTTPS connections. We need to handle TLS ourselves
	// and then wrap the connection to record the decrypted HTTP traffic.
	rr.transport.DialTLSContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		// First establish the TCP connection
		plainConn, err := transport.DialContext(ctx, network, addr)
		if err != nil {
			return nil, err
		}

		// Get the recording metadata from context
		rec, ok := roundTripRecordingFromContext(ctx)
		if !ok {
			plainConn.Close()
			return nil, errors.New("missing roundtrip meta in context")
		}

		// Determine the hostname for SNI
		colonPos := -1
		for i := len(addr) - 1; i >= 0; i-- {
			if addr[i] == ':' {
				colonPos = i
				break
			}
		}
		hostname := addr
		if colonPos != -1 {
			hostname = addr[:colonPos]
		}

		// Perform TLS handshake with the transport's TLS config (or default if nil)
		tlsConfig := clone.TLSClientConfig
		if tlsConfig == nil {
			tlsConfig = &tls.Config{MinVersion: tls.VersionTLS13}
		} else {
			tlsConfig = tlsConfig.Clone()
		}
		tlsConfig.ServerName = hostname

		tlsConn := tls.Client(plainConn, tlsConfig)
		if err := tlsConn.HandshakeContext(ctx); err != nil {
			plainConn.Close()
			return nil, err
		}

		// Wrap the TLS connection with our recorder
		// Now we'll record the decrypted HTTP traffic
		return rr.beginRecording(rec, tlsConn), nil
	}

	return rr
}

func (r *RoundTripRecorder) RoundTrip(req *http.Request) (*http.Response, error) {
	req = requestWithRoundTripRecordingContext(req)
	return r.transport.RoundTrip(req)
}

func (r *RoundTripRecorder) Recordings() []RoundTripRecording {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]RoundTripRecording, 0, len(r.recordings))
	for _, rec := range r.recordings {
		out = append(out, rec.Clone())
	}
	return out
}

func (r *RoundTripRecorder) beginRecording(rec *RoundTripRecording, conn net.Conn) net.Conn {
	recordedConn := &recordedConn{
		Conn: conn,
		mu:   &sync.Mutex{},
		rec:  rec,
	}

	recordedConn.doneFunc = func() {
		// First acquire the recordedConn's mutex to safely read rec
		recordedConn.mu.Lock()
		recCopy := *rec
		recordedConn.mu.Unlock()

		// Then acquire the RoundTripRecorder's mutex to append
		r.mu.Lock()
		defer r.mu.Unlock()
		r.recordings = append(r.recordings, recCopy)
	}

	return recordedConn
}

type RoundTripRecording struct {
	Method          string
	URL             *url.URL
	RequestCtx      context.Context
	RequestRecords  []Record
	ResponseRecords []Record
}

func (r RoundTripRecording) Clone() RoundTripRecording {
	out := r
	for i, record := range r.RequestRecords {
		out.RequestRecords[i] = record.Clone()
	}
	for i, record := range r.ResponseRecords {
		out.ResponseRecords[i] = record.Clone()
	}
	return out
}

func (r RoundTripRecording) TotalRequestBytes() int64 {
	count := int64(0)
	for _, rec := range r.RequestRecords {
		if len(rec.Data) > 0 {
			count += int64(len(rec.Data))
		}
	}
	return count
}

func (r RoundTripRecording) TotalResponseBytes() int64 {
	count := int64(0)
	for _, rec := range r.ResponseRecords {
		if len(rec.Data) > 0 {
			count += int64(len(rec.Data))
		}
	}
	return count
}

func (r RoundTripRecording) RequestBytes() []byte {
	buf := bytes.NewBuffer(make([]byte, 0, r.TotalResponseBytes()))
	for _, rec := range r.RequestRecords {
		if len(rec.Data) > 0 {
			buf.Write(rec.Data)
		}
	}
	return buf.Bytes()
}

func (r RoundTripRecording) ResponseBytes() []byte {
	buf := bytes.NewBuffer(make([]byte, 0, r.TotalResponseBytes()))
	for _, rec := range r.ResponseRecords {
		if len(rec.Data) > 0 {
			buf.Write(rec.Data)
		}
	}
	return buf.Bytes()
}

type Record struct {
	Timestamp time.Time
	Data      []byte
	Err       error
}

func (r Record) Clone() Record {
	out := r
	out.Data = bytes.Clone(r.Data)
	return out
}

type recordedConn struct {
	net.Conn

	mu       *sync.Mutex
	rec      *RoundTripRecording
	doneFunc func()
}

func (c *recordedConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if n > 0 || err != nil {
		c.mu.Lock()
		c.rec.ResponseRecords = append(c.rec.ResponseRecords, Record{
			Timestamp: time.Now(),
			Data:      bytes.Clone(p[:n]),
			Err:       err,
		})
		c.mu.Unlock()
	}
	return n, err
}

func (c *recordedConn) Write(p []byte) (int, error) {
	// write is allowed to modify p, so clone before we write.
	pClone := bytes.Clone(p)
	n, err := c.Conn.Write(p)
	if n > 0 || err != nil {
		c.mu.Lock()
		c.rec.RequestRecords = append(c.rec.RequestRecords, Record{
			Timestamp: time.Now(),
			Data:      pClone[:n],
			Err:       err,
		})
		c.mu.Unlock()
	}
	return n, err
}

func (c *recordedConn) Close() error {
	err := c.Conn.Close()
	c.doneFunc()
	return err
}

type ctxKey string

const recordingCtxKey = ctxKey("httptest.RoundTripRecorders.recording")

func requestWithRoundTripRecordingContext(req *http.Request) *http.Request {
	method := http.MethodGet
	if req.Method != "" {
		method = req.Method
	}

	ctx := context.WithValue(req.Context(), recordingCtxKey, &RoundTripRecording{
		Method:     method,
		URL:        req.URL,
		RequestCtx: req.Context(),
	})
	return req.WithContext(ctx)
}

func roundTripRecordingFromContext(ctx context.Context) (*RoundTripRecording, bool) {
	val, ok := ctx.Value(recordingCtxKey).(*RoundTripRecording)
	return val, ok
}

func MedianDeltaBetweenReads(records []Record) time.Duration {
	deltas := make([]time.Duration, 0, len(records)-1)
	for i, record := range records {
		if i == 0 {
			continue
		}

		deltas = append(deltas, record.Timestamp.Sub(records[i-1].Timestamp))
	}

	sort.Slice(deltas, func(i, j int) bool {
		return deltas[i] < deltas[j]
	})

	median := deltas[len(deltas)/2]
	return median
}
