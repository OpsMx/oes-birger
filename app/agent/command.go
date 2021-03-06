package main

import (
	"fmt"
	"io"
	"log"
	"os/exec"

	"github.com/opsmx/grpc-bidir/pkg/tunnel"
)

func makeCommandFailed(req *tunnel.CommandRequest) *tunnel.ASEventWrapper {
	return &tunnel.ASEventWrapper{
		Event: &tunnel.ASEventWrapper_CommandTermination{
			CommandTermination: &tunnel.CommandTermination{
				Id:       req.Id,
				Target:   req.Target,
				ExitCode: 127,
			},
		},
	}
}

func runCommand(dataflow chan *tunnel.ASEventWrapper, req *tunnel.CommandRequest) {
	cmd := exec.Command("sh", "-c", "echo stdout; echo 1>&2 stderr")
	stderr, err := cmd.StderrPipe()
	if err != nil {
		log.Fatal(err)
	}

	if err := cmd.Start(); err != nil {
		log.Fatal(err)
	}

	slurp, _ := io.ReadAll(stderr)
	fmt.Printf("%s\n", slurp)

	if err := cmd.Wait(); err != nil {
		log.Fatal(err)
	}
}
