package kmip

/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

import (
	"testing"

	"github.com/stretchr/testify/suite"
)

type NamesSuite struct {
	suite.Suite
}

func (s *NamesSuite) TestTagName() {
	s.Assert().Equal("OPERATION (0x42005c)", TagName(OPERATION))
	s.Assert().Equal("RESULT_STATUS (0x42007f)", TagName(RESULT_STATUS))
	// tag names are processed in sorted order, so of the names sharing
	// 0x42000f the result is always BATCH_ITEM
	s.Assert().Equal("BATCH_ITEM (0x42000f)", TagName(RESPONSE_BATCH_ITEM))
	s.Assert().Equal("unknown tag (0x54000a)", TagName(Tag(0x54000A)))
}

func (s *NamesSuite) TestTypeName() {
	s.Assert().Equal("STRUCTURE (0x01)", TypeName(STRUCTURE))
	s.Assert().Equal("ENUMERATION (0x05)", TypeName(ENUMERATION))
	s.Assert().Equal("unknown type (0x2a)", TypeName(Type(0x2A)))
}

func (s *NamesSuite) TestEnumNames() {
	s.Assert().Equal("OPERATION_ENCRYPT", OperationName(OPERATION_ENCRYPT))
	s.Assert().Equal("unknown operation (0x0000ffff)", OperationName(Enum(0xFFFF)))

	s.Assert().Equal("RESULT_STATUS_SUCCESS", ResultStatusName(RESULT_STATUS_SUCCESS))
	s.Assert().Equal("unknown result status (0x0000ffff)", ResultStatusName(Enum(0xFFFF)))

	s.Assert().Equal("RESULT_REASON_GENERAL_FAILURE", ResultReasonName(RESULT_REASON_GENERAL_FAILURE))
	s.Assert().Equal("unknown result reason (0x0000ffff)", ResultReasonName(Enum(0xFFFF)))
}

func TestNamesSuite(t *testing.T) {
	suite.Run(t, new(NamesSuite))
}
