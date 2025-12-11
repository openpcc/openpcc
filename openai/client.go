package openai

import (
	"context"
	"fmt"

	"github.com/openai/openai-go/v3"
	"github.com/openai/openai-go/v3/option"
	"github.com/openpcc/openpcc"
)

const openAIBaseURL = "http://confsec.invalid/v1"

// Client embeds an OpenAI client that is configured to routes requests through an OpenPCC client
// for private request handling.
//
// It can be used as a drop-in replacement for the official OpenAI client with one important caveat:
// This client needs to be closed by calling [Close] after it's no longer used. Failure to close
// the client will result in lost credits.
type Client struct {
	*openai.Client

	opccClient *openpcc.Client
}

func NewClient(ctx context.Context, apiKey, apiURL string, options ...openpcc.Option) (*Client, error) {
	opccClient, err := openpcc.New(ctx, apiKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create openpcc client: %w", err)
	}

	httpClient := opccClient.HTTPClient()

	aiClient := openai.NewClient(
		option.WithAPIKey(""), // generally not used.
		option.WithBaseURL(openAIBaseURL),
		option.WithHTTPClient(httpClient),
	)

	return &Client{
		Client:     &aiClient,
		opccClient: opccClient,
	}, nil
}

func (c *Client) OpenPCCClient() *openpcc.Client {
	return c.opccClient
}

func (c *Client) Close(ctx context.Context) error {
	return c.opccClient.Close(ctx)
}
