package main

import (
	"errors"
	"io"
	"os"
)

func main() {
	cfg, err := LoadConfig(os.Args[1:])
	if err != nil {
		if errors.Is(err, ErrHelp) {
			_, _ = io.WriteString(os.Stdout, err.Error()+"\n")
			return
		}
		_, _ = io.WriteString(os.Stderr, "[ippeek] config error: "+err.Error()+"\n")
		os.Exit(1)
	}

	if cfg.ShowVersion {
		_, _ = io.WriteString(os.Stdout, "ippeek "+version+"\n")
		return
	}

	prober := NewProber(cfg.V4Probes, cfg.V6Probes, cfg.ProbeTimeout, cfg.CacheTTL)
	resolver := NewResolver(OSInterfaceProvider{}, prober)

	if err := runServer(cfg, resolver); err != nil {
		_, _ = io.WriteString(os.Stderr, "[ippeek] server error: "+err.Error()+"\n")
		os.Exit(1)
	}
}
