package main

import (
	"fmt"
	"os"

	"rhodium/agent/capture"
)

func main() {
	if err := capture.Run(); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}
