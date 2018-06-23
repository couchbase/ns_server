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
	"errors"
	"io"
	"os"
	"os/exec"
	"sync"
)

var (
	// ErrClosed is an error returned by Process methods on attempt to do
	// something with a stream that is already closed.
	ErrClosed = errors.New("closed")
)

// Process is a thin wrapper around exec.Cmd and the pipes to communicate with
// the process represented by the exec.Cmd.
type Process struct {
	cmd *exec.Cmd

	stdinMu *sync.Mutex
	stdin   io.WriteCloser

	stdout io.ReadCloser
	stderr io.ReadCloser
}

// StartProcess starts a process given a path and a list of arguments to pass
// to the executable.
func StartProcess(path string, args []string) (*Process, error) {
	// files we'll need after fork
	keepFiles := ([]io.Closer)(nil)

	// files we need to close after fork
	closeFiles := ([]io.Closer)(nil)

	defer func() {
		files := append(keepFiles, closeFiles...)
		closeAll(files)
	}()

	keepFile := func(file io.Closer) {
		keepFiles = append(keepFiles, file)
	}

	closeFile := func(file io.Closer) {
		closeFiles = append(closeFiles, file)
	}

	stdinR, stdinW, err := os.Pipe()
	if err != nil {
		return nil, err
	}
	keepFile(stdinW)
	closeFile(stdinR)

	stdoutR, stdoutW, err := os.Pipe()
	if err != nil {
		return nil, err
	}
	keepFile(stdoutR)
	closeFile(stdoutW)

	stderrR, stderrW, err := os.Pipe()
	if err != nil {
		return nil, err
	}
	keepFile(stderrR)
	closeFile(stderrW)

	cmd := exec.Command(path, args...)
	cmd.Stdin = stdinR
	cmd.Stdout = stdoutW
	cmd.Stderr = stderrW

	SetPgid(cmd)

	err = cmd.Start()
	if err != nil {
		return nil, err
	}

	// don't close fds that we need
	keepFiles = nil

	p := &Process{
		cmd: cmd,

		stdinMu: &sync.Mutex{},
		stdin:   &CloseOnce{File: stdinW},

		stdout: stdoutR,
		stderr: stderrR,
	}

	return p, nil
}

// Write writes to the standard input of the process.
func (p *Process) Write(data []byte) (int, error) {
	p.stdinMu.Lock()
	defer p.stdinMu.Unlock()

	if p.stdin == nil {
		return 0, ErrClosed
	}

	return p.stdin.Write(data)
}

// Close closes the standard input of the underlying process.
func (p *Process) Close() error {
	p.stdinMu.Lock()
	defer p.stdinMu.Unlock()

	if p.stdin == nil {
		return ErrClosed
	}

	err := p.stdin.Close()
	p.stdin = nil

	return err
}

// GetStdout returns an io.Reader that can be used to read from the process'
// standard output.
func (p *Process) GetStdout() io.Reader {
	return p.stdout
}

// GetStderr returns an io.Reader that can be used to read from the process'
// standard error.
func (p *Process) GetStderr() io.Reader {
	return p.stderr
}

// Kill kills the process brutally.
func (p *Process) Kill() error {
	return KillPgroup(p.cmd)
}

// Wait waits for the process to terminate.
func (p *Process) Wait() error {
	err := p.cmd.Wait()
	if p.cmd.ProcessState != nil {
		err = nil
	}

	return err
}

// GetExitStatus returns an exit status of the process once it has
// terminated. Needs to be called after Wait.
func (p *Process) GetExitStatus() int {
	return GetExitStatus(p.cmd)
}

func closeAll(files []io.Closer) {
	for _, f := range files {
		f.Close()
	}
}
