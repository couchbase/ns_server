package kmip

/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

import (
	"crypto/tls"
	"fmt"
	"net"
	"time"

	"github.com/pkg/errors"
)

// Client implements basic KMIP client
//
// Client is not safe for concurrent use
type Client struct {
	// Server endpoint as "host:port"
	Endpoint string

	// TLS client config
	TLSConfig *tls.Config

	// KMIP version to use
	//
	// Defaults to DefaultSupportedVersions[0] if not set
	Version ProtocolVersion

	// Network timeouts
	ReadTimeout, WriteTimeout, DialTimeout time.Duration

	conn *tls.Conn
	e    *Encoder
	d    *Decoder
}

// Connect establishes connection with the server
func (c *Client) Connect() error {
	var err error

	dialer := &net.Dialer{}
	if c.DialTimeout != 0 {
		dialer.Timeout = c.DialTimeout
	}

	if c.conn, err = tls.DialWithDialer(dialer, "tcp", c.Endpoint, c.TLSConfig); err != nil {
		return errors.Wrap(err, "error dialing connection")
	}

	if c.ReadTimeout != 0 {
		_ = c.conn.SetReadDeadline(time.Now().Add(c.ReadTimeout))
	}

	if c.WriteTimeout != 0 {
		_ = c.conn.SetWriteDeadline(time.Now().Add(c.WriteTimeout))
	}

	if err = c.conn.Handshake(); err != nil {
		return errors.Wrap(err, "error running tls handshake")
	}

	var zeroVersion ProtocolVersion
	if c.Version == zeroVersion {
		c.Version = DefaultSupportedVersions[0]
	}

	c.e = NewEncoder(c.conn)
	c.d = NewDecoder(c.conn)

	return nil
}

// Close connection to the server
func (c *Client) Close() error {
	if c.conn == nil {
		return nil
	}

	err := c.conn.Close()
	c.conn = nil

	return err
}

// DiscoverVersions with the server
func (c *Client) DiscoverVersions(versions []ProtocolVersion) (serverVersions []ProtocolVersion, err error) {
	var resp interface{}
	resp, err = c.Send(OPERATION_DISCOVER_VERSIONS,
		DiscoverVersionsRequest{
			ProtocolVersions: versions,
		})

	if err != nil {
		return
	}

	serverVersions = resp.(DiscoverVersionsResponse).ProtocolVersions
	return
}

// Send request to server and deliver response/error back
//
// Request payload should be passed as req, and response payload will be
// returned back as resp. Operation will be sent as a batch with single
// item.
//
// Send is a generic method, it's better to implement specific methods for
// each operation (use DiscoverVersions as example).
func (c *Client) Send(operation Enum, req interface{}) (resp interface{}, err error) {
	if c.conn == nil {
		err = errors.New("not connected")
		return
	}

	request := &Request{
		Header: RequestHeader{
			Version:    c.Version,
			BatchCount: 1,
		},
		BatchItems: []RequestBatchItem{
			{
				Operation:      operation,
				RequestPayload: req,
			},
		},
	}

	if c.WriteTimeout != 0 {
		_ = c.conn.SetWriteDeadline(time.Now().Add(c.WriteTimeout))
	}

	err = c.e.Encode(request)
	if err != nil {
		err = errors.Wrap(err, "error writing request")
		return
	}

	if c.ReadTimeout != 0 {
		_ = c.conn.SetReadDeadline(time.Now().Add(c.ReadTimeout))
	}

	var response Response

	err = c.d.Decode(&response)
	if err != nil {
		err = errors.Wrap(err, "error reading response")
		return
	}

	return responsePayload(operation, &response)
}

// responsePayload verifies the response to a single item batch and returns
// payload of that item, or the error the server has reported
func responsePayload(operation Enum, response *Response) (resp interface{}, err error) {
	if response.Header.BatchCount != 1 {
		err = errors.Errorf("unexpected response batch count: %d", response.Header.BatchCount)
		return
	}

	if len(response.BatchItems) != 1 {
		err = errors.Errorf("unexpected response batch items: %d", len(response.BatchItems))
		return
	}

	batchItem := response.BatchItems[0]

	// result status is checked before the operation: a failed batch item
	// might carry no operation at all (see ResponseBatchItem), and the error
	// the server reports is way more useful than a complaint about the
	// operation being missing
	if batchItem.ResultStatus != RESULT_STATUS_SUCCESS {
		err = batchItemError(operation, batchItem)
		return
	}

	if batchItem.Operation != operation {
		err = errors.Errorf("unexpected response operation: expecting %s, but %s was encountered",
			OperationName(operation), OperationName(batchItem.Operation))
		return
	}

	resp = batchItem.ResponsePayload
	return
}

// batchItemError builds an error out of a batch item which didn't succeed
//
// Result Message is optional in KMIP and plenty of servers never send it, so
// the error is built out of everything the server did report instead of the
// message alone, otherwise the caller is left with an empty error.
func batchItemError(operation Enum, item ResponseBatchItem) error {
	details := ResultStatusName(item.ResultStatus)

	if item.ResultReason != 0 {
		details += ", " + ResultReasonName(item.ResultReason)
	}

	msg := fmt.Sprintf("%s failed (%s)", OperationName(operation), details)

	if item.ResultMessage != "" {
		msg += ": " + item.ResultMessage
	}

	return wrapError(errors.New(msg), item.ResultReason)
}
