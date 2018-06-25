// @author Couchbase <info@couchbase.com>
// @copyright 2015-2018 Couchbase, Inc.
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
	"bufio"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"path"
	"strconv"
)

type childExitedError int

func (e childExitedError) Error() string {
	return fmt.Sprintf("child process exited with status %d", int(e))
}

func (e childExitedError) exitStatus() int {
	return int(e)
}

const (
	stdin  = "stdin"
	stdout = "stdout"
	stderr = "stderr"
)

type portSpec struct {
	cmd  string
	args []string

	windowSize  int
	interactive bool
}

type loopState struct {
	unackedBytes int
	pendingOp    <-chan error

	childStreams map[string]*AsyncReader
	pendingWrite <-chan error

	childDone    <-chan error
	shuttingDown bool
}

type port struct {
	child     *Process
	childSpec portSpec

	opsReader *OpsReader

	parentWriter       *AsyncWriter
	parentWriterStream *NetStringWriter

	childStdin  *AsyncWriter
	childStdout *AsyncReader
	childStderr *AsyncReader

	state loopState
}

func newPort(spec portSpec) *port {
	return &port{childSpec: spec}
}

func (p *port) startChild() error {
	child, err := StartProcess(p.childSpec.cmd, p.childSpec.args)
	if err != nil {
		return err
	}

	p.child = child

	p.startChildObserver()

	return nil
}

func (p *port) startChildObserver() {
	done := make(chan error)

	go func() {
		done <- p.child.Wait()
		close(done)
	}()

	p.state.childDone = done
}

func (p *port) getChildDone() <-chan error {
	// this makes sure that stderr and stdout are read to completion
	// before we report the child dead
	if len(p.state.childStreams) != 0 {
		return nil
	}

	return p.state.childDone
}

func (p *port) startWorkers() {
	packetReader := (PacketReader)(NewNetStringReader(os.Stdin))
	if p.childSpec.interactive {
		packetReader = newInteractiveReader()
	}

	p.opsReader = NewOpsReader(packetReader)

	p.parentWriterStream = NewNetStringWriter(os.Stdout)
	p.parentWriter = NewAsyncWriter(p.parentWriterStream)

	p.childStdin = NewAsyncWriter(&SimpleVectorWriter{p.child})
	p.childStdout = NewAsyncReader(p.child.GetStdout())
	p.childStderr = NewAsyncReader(p.child.GetStderr())
}

func (p *port) terminateWorkers() {
	p.opsReader.Cancel()
	p.parentWriter.Cancel()
	p.childStdin.Cancel()
	p.childStdout.Cancel()
	p.childStderr.Cancel()

	p.opsReader.Wait()
	p.parentWriter.Wait()
	p.childStdin.Wait()
	p.childStdout.Wait()
	p.childStderr.Wait()
}

func (p *port) initLoopState() {
	p.state.unackedBytes = 0
	p.state.pendingOp = nil

	p.state.childStreams = make(map[string]*AsyncReader)
	p.state.childStreams[stdout] = p.childStdout
	p.state.childStreams[stderr] = p.childStderr
	p.state.pendingWrite = nil
	p.state.shuttingDown = false
}

func (p *port) getOps() <-chan *Op {
	if p.state.shuttingDown {
		return nil
	}

	if p.state.pendingOp != nil {
		return nil
	}

	return p.opsReader.GetOpsChan()
}

func (p *port) isWindowFull() bool {
	return p.state.unackedBytes >= p.childSpec.windowSize
}

func (p *port) getChildStream(tag string) <-chan []byte {
	if p.state.pendingWrite != nil {
		return nil
	}

	if p.isWindowFull() &&
		// shutdown request implicitly acks everything
		!p.state.shuttingDown {
		return nil
	}

	stream, ok := p.state.childStreams[tag]
	if ok {
		return stream.GetReadChan()
	}

	return nil
}

func (p *port) parentWrite(data ...[]byte) {
	p.state.pendingWrite = p.parentWriter.Writev(data...)
}

func (p *port) parentSyncWrite(data ...[]byte) error {
	return <-p.parentWriter.Writev(data...)
}

func (p *port) proxyChildOutput(tag string, data []byte) {
	p.state.unackedBytes += len(data)
	p.parentWrite([]byte(tag), []byte(":"), data)
}

func (p *port) abortPendingOp() {
	if p.state.pendingOp != nil {
		p.handleOpResult(errors.New("child exited"))
	}
}

func (p *port) handleOp(op *Op) {
	var ch <-chan error

	switch op.Name {
	case "ack":
		ch = p.handleAck(op.Arg)
	case "write":
		ch = p.handleWrite(op.Arg)
	case "close":
		ch = p.handleCloseStream(op.Arg)
	case "shutdown":
		ch = p.handleShutdown()
	default:
		ch = p.handleUnknown(op.Name)
	}

	p.state.pendingOp = ch
}

func (p *port) handleShutdown() <-chan error {
	ch := make(chan error, 1)

	err := p.child.Kill()
	if err != nil {
		ch <- err
		return ch
	}

	p.noteShuttingDown()

	// Note that the channel is empty. The operation is responded to once
	// we see the child terminate.
	return ch
}

func (p *port) handleWrite(data []byte) <-chan error {
	return p.childStdin.Writev(data)
}

func (p *port) handleAck(data []byte) <-chan error {
	ch := make(chan error, 1)

	if len(data) == 0 {
		ch <- fmt.Errorf("need argument")
		return ch
	}

	count, err := strconv.Atoi(string(data))
	if err != nil {
		ch <- fmt.Errorf("invalid value '%s'", string(data))
		return ch
	}

	p.state.unackedBytes -= count
	if p.state.unackedBytes < 0 {
		p.state.unackedBytes = 0
	}

	ch <- nil
	return ch
}

func (p *port) handleCloseStream(data []byte) <-chan error {
	ch := make(chan error, 1)
	stream := string(data)

	switch stream {
	case stdin:
		p.childStdin.Cancel()
		p.childStdin.Wait()
		err := p.child.Close()
		ch <- err
	default:
		ch <- fmt.Errorf("unknown stream '%s'", stream)
	}

	return ch
}

func (p *port) handleUnknown(cmd string) <-chan error {
	ch := make(chan error, 1)
	ch <- fmt.Errorf("unknown command '%s'", cmd)

	return ch
}

func (p *port) handleOpResult(err error) error {
	resp := "ok"
	if err != nil {
		resp = fmt.Sprintf("error:%s", err.Error())
	}

	return p.parentSyncWrite([]byte(resp))
}

func (p *port) noteOpDone() {
	p.state.pendingOp = nil
}

func (p *port) noteWriteDone() {
	p.state.pendingWrite = nil
}

func (p *port) noteShuttingDown() {
	p.state.shuttingDown = true
}

func (p *port) handleChildRead(tag string, data []byte, ok bool) {
	if !ok {
		stream := p.state.childStreams[tag]
		delete(p.state.childStreams, tag)
		p.reportEOF(tag, stream.GetError())
		return
	}

	p.proxyChildOutput(tag, data)
}

func (p *port) reportEOF(tag string, reason error) {
	msg := [][]byte{[]byte("eof:"), []byte(tag)}
	if reason != io.EOF {
		msg = append(msg, []byte(":"), []byte(reason.Error()))
	}

	p.parentWrite(msg...)
}

func (p *port) loop() error {
	err := p.startChild()
	if err != nil {
		return fmt.Errorf("failed to start child: %s", err.Error())
	}
	defer p.child.Kill()

	p.startWorkers()
	defer p.terminateWorkers()

	p.initLoopState()
	defer p.abortPendingOp()

	for {
		select {
		case op, ok := <-p.getOps():
			if !ok {
				err := p.opsReader.GetError()
				if err == io.EOF {
					return nil
				}

				return fmt.Errorf("read failed: %s", err)
			}

			p.handleOp(op)
		case err := <-p.state.pendingOp:
			p.noteOpDone()
			err = p.handleOpResult(err)
			if err != nil {
				return fmt.Errorf(
					"failed to write to parent: %s", err.Error())
			}
		case err := <-p.getChildDone():
			if err != nil {
				return err
			}

			if p.state.shuttingDown {
				// respond to the shutdown request
				p.handleOpResult(nil)
				p.noteOpDone()
			}

			status := p.child.GetExitStatus()
			if status == 0 {
				return nil
			}
			return childExitedError(status)
		case data, ok := <-p.getChildStream(stdout):
			p.handleChildRead(stdout, data, ok)
		case data, ok := <-p.getChildStream(stderr):
			p.handleChildRead(stderr, data, ok)
		case err := <-p.state.pendingWrite:
			p.noteWriteDone()
			if err != nil {
				return fmt.Errorf(
					"parent write failed: %s", err.Error())
			}
		}
	}
}

type argsFlag []string

func (args *argsFlag) String() string {
	return fmt.Sprintf("%v", *args)
}

func (args *argsFlag) Set(v string) error {
	*args = append(*args, v)
	return nil
}

type cmdFlag string

func (c *cmdFlag) String() string {
	return string(*c)
}

func (c *cmdFlag) Set(v string) error {
	if v == "" {
		return errors.New("-cmd can't be empty")
	}

	if path.IsAbs(v) {
		*c = cmdFlag(v)
	} else {
		abs, err := exec.LookPath(v)
		if err != nil {
			return fmt.Errorf("failed to find '%s' in path: %s", v, err.Error())
		}

		*c = cmdFlag(abs)
	}

	return nil
}

func getCmdFromEnv() (string, []string) {
	rawArgs := os.Getenv("GOPORT_ARGS")
	if rawArgs == "" {
		log.Fatalf("GOPORT_ARGS is empty")
	}

	var args []string

	err := json.Unmarshal([]byte(rawArgs), &args)
	if err != nil {
		log.Fatalf("couldn't unmarshal GOPORT_ARGS(%s): %s", rawArgs, err.Error())
	}

	if len(args) < 1 {
		log.Fatalf("missing executable")
	}

	return args[0], args[1:]
}

type interactiveReader struct {
	scanner *bufio.Scanner
}

func newInteractiveReader() *interactiveReader {
	return &interactiveReader{bufio.NewScanner(os.Stdin)}
}

func (r *interactiveReader) ReadPacket() ([]byte, error) {
	read := r.scanner.Scan()
	if read {
		return r.scanner.Bytes(), nil
	}

	err := r.scanner.Err()
	if err != nil {
		return nil, err
	}

	return nil, io.EOF
}

func main() {
	var windowSize int

	var cmd string
	var args []string

	var interactive bool

	flag.IntVar(&windowSize, "window-size", 64*1024, "window size")
	flag.BoolVar(&interactive, "interactive", false,
		"run in interactive mode")
	flag.Var((*cmdFlag)(&cmd), "cmd", "command to execute")
	flag.Var((*argsFlag)(&args), "args", "command arguments")
	flag.Parse()

	log.SetPrefix("[goport] ")

	if windowSize < 0 {
		log.Fatalf("window size can't be less than zero")
	}

	if cmd == "" {
		cmd, args = getCmdFromEnv()
	}

	log.SetPrefix(fmt.Sprintf("[goport(%s)] ", cmd))

	port := newPort(portSpec{
		cmd:         cmd,
		args:        args,
		windowSize:  windowSize,
		interactive: interactive,
	})

	err := port.loop()
	if err != nil {
		status := 1

		childError, ok := err.(childExitedError)
		if ok {
			status = childError.exitStatus()
		}

		log.Print(err.Error())
		os.Exit(status)
	}
}
