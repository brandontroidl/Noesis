// Copyright (c) Cathexis Development
// SPDX-License-Identifier: GPL-2.0-only
//
// noesis — P10 IRC services framework for Cathexis IRCd.
//
// Acid links to Cathexis via P10 over TLS with HMAC-SHA256 authentication.
// Provides modular pseudo-client services (weather, trivia, quotes,
// limitserv, trapbot, ctcp, vizon, xmas).
//
// Build: go build -ldflags="-s -w" -o internets .

package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/brandontroidl/noesis/config"
	"github.com/brandontroidl/noesis/modules"
	"github.com/brandontroidl/noesis/server"
)

const (
	Version   = "1.1.0"
	BuildName = "noesis"
)

func main() {
	configPath := flag.String("config", "noesis.toml", "Path to configuration file")
	showVersion := flag.Bool("version", false, "Show version and exit")
	flag.Parse()

	if *showVersion {
		fmt.Printf("%s version %s\n", BuildName, Version)
		os.Exit(0)
	}

	log.SetFlags(log.LstdFlags | log.Lmicroseconds)
	log.Printf("%s v%s starting", BuildName, Version)

	// Load configuration
	cfg, err := config.Load(*configPath)
	if err != nil {
		log.Fatalf("Failed to load config %s: %v", *configPath, err)
	}

	log.Printf("Configuration loaded from %s", *configPath)

	// Create and initialize server
	srv, err := server.New(cfg)
	if err != nil {
		log.Fatalf("Failed to create server: %v", err)
	}

	// Register all service modules
	modules.RegisterAll(srv)

	// Signal handling for clean shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		sig := <-sigChan
		log.Printf("Received signal %s, shutting down", sig)
		srv.Shutdown()
	}()

	// Connect and run with auto-reconnect
	srv.RunWithReconnect()

	log.Printf("%s shutdown complete", BuildName)
}
