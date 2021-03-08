package main

import (
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"syscall"

	"github.com/opsmx/grpc-bidir/pkg/tunnel"
	"golang.org/x/net/context"
)

func outputSender(id int, c chan *outputMessage, in io.Reader) {
	buffer := make([]byte, 10240)
	for {
		n, err := in.Read(buffer)
		if n > 0 {
			c <- &outputMessage{id: id, value: string(buffer[:n]), closed: false}
		}
		if err == io.EOF {
			c <- &outputMessage{id: id, value: "", closed: true}
		}
		if err != nil {
			log.Printf("Got %v in read", err)
			c <- &outputMessage{id: id, value: "", closed: true}
		}
	}
}

type outputMessage struct {
	id     int
	value  string
	closed bool
}

func makeCommandFailed(req *tunnel.CommandRequest, err error, message string) *tunnel.ASEventWrapper {
	var msg string
	if err != nil {
		msg = fmt.Sprintf("%s: %v", message, err)
	} else {
		msg = message
	}
	return &tunnel.ASEventWrapper{
		Event: &tunnel.ASEventWrapper_CommandTermination{
			CommandTermination: &tunnel.CommandTermination{
				Id:       req.Id,
				Target:   req.Target,
				ExitCode: 127,
				Message:  msg,
			},
		},
	}
}

func makeCommandTermination(req *tunnel.CommandRequest, exitstatus int) *tunnel.ASEventWrapper {
	return &tunnel.ASEventWrapper{
		Event: &tunnel.ASEventWrapper_CommandTermination{
			CommandTermination: &tunnel.CommandTermination{
				Id:       req.Id,
				Target:   req.Target,
				ExitCode: int32(exitstatus),
			},
		},
	}
}

func makeCommandData(req *tunnel.CommandRequest, data []byte, source int) *tunnel.ASEventWrapper {
	var channel tunnel.CommandData_Channel
	if source == 1 {
		channel = tunnel.CommandData_STDOUT
	} else {
		channel = tunnel.CommandData_STDERR
	}
	return &tunnel.ASEventWrapper{
		Event: &tunnel.ASEventWrapper_CommandData{
			CommandData: &tunnel.CommandData{
				Id:      req.Id,
				Target:  req.Target,
				Body:    data,
				Channel: channel,
			},
		},
	}
}

func runCommand(dataflow chan *tunnel.ASEventWrapper, req *tunnel.CommandRequest) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	agg := make(chan *outputMessage)

	cmd := exec.CommandContext(ctx, os.Args[1], os.Args[2:]...)

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		dataflow <- makeCommandFailed(req, err, "StdoutPipe()")
		return
	}

	stderr, err := cmd.StderrPipe()
	if err != nil {
		dataflow <- makeCommandFailed(req, err, "StderrPipe()")
		return
	}

	go outputSender(1, agg, stdout)
	go outputSender(2, agg, stderr)

	err = cmd.Start()
	if err != nil {
		// this path will occur if the command can't be found.  Other errors
		// are possible, but this is most likely.
		dataflow <- makeCommandFailed(req, err, "Start()")
		return
	}

	activeCount := 2
	for msg := range agg {
		if msg.closed {
			log.Printf("Channel %d closed", msg.id)
			activeCount--
			if activeCount == 0 {
				break
			}
		} else {
			log.Printf("channel %d sent %s", msg.id, msg.value)
		}
	}

	if err := cmd.Wait(); err != nil {
		if exiterr, ok := err.(*exec.ExitError); ok {
			// The program has exited with an exit code != 0
			if status, ok := exiterr.Sys().(syscall.WaitStatus); ok {
				dataflow <- makeCommandTermination(req, status.ExitStatus())
				return
			}
		} else {
			dataflow <- makeCommandFailed(req, err, "Wait()")
			return
		}
	}

	dataflow <- makeCommandTermination(req, 0)
}
