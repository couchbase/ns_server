package kmip

/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

import (
	"testing"
	"time"

	"github.com/stretchr/testify/suite"
)

type ClientSuite struct {
	suite.Suite
}

func (s *ClientSuite) response(items ...ResponseBatchItem) *Response {
	return &Response{
		Header: ResponseHeader{
			Version:    DefaultSupportedVersions[0],
			TimeStamp:  time.Unix(1600000000, 0),
			BatchCount: int32(len(items)),
		},
		BatchItems: items,
	}
}

func (s *ClientSuite) TestResponsePayload() {
	payload := DiscoverVersionsResponse{ProtocolVersions: DefaultSupportedVersions}

	resp, err := responsePayload(OPERATION_DISCOVER_VERSIONS, s.response(ResponseBatchItem{
		Operation:       OPERATION_DISCOVER_VERSIONS,
		ResultStatus:    RESULT_STATUS_SUCCESS,
		ResponsePayload: payload,
	}))
	s.Assert().NoError(err)
	s.Assert().Equal(payload, resp)
}

// TestResponsePayloadFailureNoOperation checks that the failure reported by a
// server which didn't send the operation back (it might not even know what the
// operation was, see ResponseBatchItem) is passed on to the caller
func (s *ClientSuite) TestResponsePayloadFailureNoOperation() {
	_, err := responsePayload(OPERATION_ENCRYPT, s.response(ResponseBatchItem{
		ResultStatus:  RESULT_STATUS_OPERATION_FAILED,
		ResultReason:  RESULT_REASON_INVALID_MESSAGE,
		ResultMessage: "bad request",
	}))
	s.Assert().EqualError(err, "OPERATION_ENCRYPT failed (RESULT_STATUS_OPERATION_FAILED, "+
		"RESULT_REASON_INVALID_MESSAGE): bad request")
	s.Assert().Equal(RESULT_REASON_INVALID_MESSAGE, err.(Error).ResultReason())
}

func (s *ClientSuite) TestResponsePayloadUnexpectedOperation() {
	_, err := responsePayload(OPERATION_ENCRYPT, s.response(ResponseBatchItem{
		Operation:    OPERATION_DECRYPT,
		ResultStatus: RESULT_STATUS_SUCCESS,
	}))
	s.Assert().EqualError(err, "unexpected response operation: expecting OPERATION_ENCRYPT, "+
		"but OPERATION_DECRYPT was encountered")
}

func (s *ClientSuite) TestResponsePayloadUnexpectedBatch() {
	_, err := responsePayload(OPERATION_ENCRYPT, s.response())
	s.Assert().EqualError(err, "unexpected response batch count: 0")

	response := s.response(ResponseBatchItem{}, ResponseBatchItem{})
	response.Header.BatchCount = 1
	_, err = responsePayload(OPERATION_ENCRYPT, response)
	s.Assert().EqualError(err, "unexpected response batch items: 2")
}

func (s *ClientSuite) TestBatchItemError() {
	err := batchItemError(OPERATION_ENCRYPT, ResponseBatchItem{
		Operation:     OPERATION_ENCRYPT,
		ResultStatus:  RESULT_STATUS_OPERATION_FAILED,
		ResultReason:  RESULT_REASON_ITEM_NOT_FOUND,
		ResultMessage: "no such key",
	})
	s.Assert().EqualError(err, "OPERATION_ENCRYPT failed (RESULT_STATUS_OPERATION_FAILED, "+
		"RESULT_REASON_ITEM_NOT_FOUND): no such key")
	s.Assert().Equal(RESULT_REASON_ITEM_NOT_FOUND, err.(Error).ResultReason())
}

func (s *ClientSuite) TestBatchItemErrorNoResultMessage() {
	// Result Message is optional and many servers never send one, the error
	// should still say what happened
	err := batchItemError(OPERATION_ENCRYPT, ResponseBatchItem{
		ResultStatus: RESULT_STATUS_OPERATION_FAILED,
		ResultReason: RESULT_REASON_PERMISSION_DENIED,
	})
	s.Assert().EqualError(err,
		"OPERATION_ENCRYPT failed (RESULT_STATUS_OPERATION_FAILED, RESULT_REASON_PERMISSION_DENIED)")
	s.Assert().Equal(RESULT_REASON_PERMISSION_DENIED, err.(Error).ResultReason())
}

func (s *ClientSuite) TestBatchItemErrorNoResultReason() {
	err := batchItemError(OPERATION_GET, ResponseBatchItem{
		ResultStatus: RESULT_STATUS_OPERATION_PENDING,
	})
	s.Assert().EqualError(err, "OPERATION_GET failed (RESULT_STATUS_OPERATION_PENDING)")
}

func TestClientSuite(t *testing.T) {
	suite.Run(t, new(ClientSuite))
}
