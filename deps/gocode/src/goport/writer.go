// @author Couchbase <info@couchbase.com>
// @copyright 2018 Couchbase, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
package main

import (
	"io"
)

// VectorWriter is an interface for objects that support writing a "vector" of
// data chunks without having to concatenate the chunks first.
type VectorWriter interface {
	// Writev writes a vector of data chunks to underlying object. If
	// error is returned, no assumptions are made about the amount of data
	// that actually was written.
	Writev(...[]byte) error
}

// SimpleVectorWriter wraps any io.Writer and provides VectorWriter interface.
type SimpleVectorWriter struct {
	io.Writer
}

// Writev writes a vector of data chunks to underlying io.Writer.
func (w *SimpleVectorWriter) Writev(data ...[]byte) error {
	for _, chunk := range data {
		_, err := w.Write(chunk)
		if err != nil {
			return err
		}
	}

	return nil
}
