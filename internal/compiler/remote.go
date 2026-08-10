package compiler

import (
	"context"
	"errors"
	"fmt"
	"os"
)

type RemoteProvider string

const (
	RemoteProviderOpenAI    RemoteProvider = "openai"
	RemoteProviderAnthropic RemoteProvider = "anthropic"
	RemoteProviderGemini    RemoteProvider = "gemini"
)

var ErrBackendNotImplemented = errors.New("remote backend is not implemented")

type RemoteBackend struct {
	provider   RemoteProvider
	envVarName string
	model      string
}

func NewRemoteBackend(provider RemoteProvider, envVarName string, model string) *RemoteBackend {
	if envVarName == "" {
		switch provider {
		case RemoteProviderOpenAI:
			envVarName = "OPENAI_API_KEY"
		case RemoteProviderAnthropic:
			envVarName = "ANTHROPIC_API_KEY"
		case RemoteProviderGemini:
			envVarName = "GEMINI_API_KEY"
		}
	}
	return &RemoteBackend{
		provider:   provider,
		envVarName: envVarName,
		model:      model,
	}
}

func (b *RemoteBackend) Name() string {
	return string(b.provider)
}

func (b *RemoteBackend) Health(ctx context.Context) error {
	token := os.Getenv(b.envVarName)
	if token == "" {
		return fmt.Errorf("%w: missing environment variable %s for remote provider %s", ErrBackendUnavailable, b.envVarName, b.provider)
	}
	return nil
}

func (b *RemoteBackend) Analyze(ctx context.Context, req *AnalysisRequest) (*AnalysisResponse, error) {
	if err := b.Health(ctx); err != nil {
		return nil, err
	}

	return nil, fmt.Errorf("%w: provider %s is explicitly unsupported/unimplemented in Phase 0.5-5 baseline", ErrBackendNotImplemented, b.provider)
}
