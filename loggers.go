package acmev2

import (
	"fmt"
	"os"
)

type StdoutLogger struct{}

func (s StdoutLogger) Log(msg interface{}) {
	fmt.Println(msg)
}

type StderrLogger struct{}

func (s StderrLogger) Log(msg interface{}) {
	fmt.Fprintln(os.Stderr, msg)
}
