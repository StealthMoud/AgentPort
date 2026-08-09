package main

import (
	"testing"

	"github.com/StealthMoud/AgentPort/internal/cli"
)

func TestMainCmdInit(t *testing.T) {
	cmd := cli.NewRootCmd()
	if cmd == nil {
		t.Fatalf("expected non-nil root command")
	}
	if cmd.Use != "agentport" {
		t.Errorf("expected root command use 'agentport', got %s", cmd.Use)
	}
}
