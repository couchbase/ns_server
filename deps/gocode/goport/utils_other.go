// @author Couchbase <info@couchbase.com>
// @copyright 2015-Present Couchbase, Inc.
//
// Use of this software is governed by the Business Source License included in
// the file licenses/BSL-Couchbase.txt.  As of the Change Date specified in that
// file, in accordance with the Business Source License, use of this software
// will be governed by the Apache License, Version 2.0, included in the file
// licenses/APL2.txt.

// +build !linux,!darwin,!freebsd,!solaris,!netbsd,!openbsd

package main

import (
	"os/exec"
)

func doSetPgid(_ *exec.Cmd) {
}

func doSetCgroup(_ *exec.Cmd, _ uintptr) {
}

func doKillPgroup(cmd *exec.Cmd) error {
	return cmd.Process.Kill()
}
