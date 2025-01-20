// @author Couchbase <info@couchbase.com>
// @copyright 2025-Present Couchbase, Inc.
//
// Use of this software is governed by the Business Source License included in
// the file licenses/BSL-Couchbase.txt.  As of the Change Date specified in that
// file, in accordance with the Business Source License, use of this software
// will be governed by the Apache License, Version 2.0, included in the file
// licenses/APL2.txt.

// +build linux

package main

import (
	"os/exec"
	"syscall"
)

func doSetPgid(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
}

func doSetCgroup(cmd *exec.Cmd, fd uintptr) {
	cmd.SysProcAttr = &syscall.SysProcAttr{CgroupFD: int(fd), UseCgroupFD: true}
}

func doKillPgroup(cmd *exec.Cmd) error {
	return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
}
