package openai_test

import (
	"os"
	"testing"

	origopenai "github.com/openai/openai-go/v3"
	"github.com/openpcc/openpcc"
	"github.com/openpcc/openpcc/openai"
	"github.com/stretchr/testify/require"
)

func TestClient(t *testing.T) {
	model := os.Getenv("OPENAI_MODEL")
	if model == "" {
		t.Skip("skipping, no OPENAI_MODEL set")
	}

	apiKey := os.Getenv("API_KEY")
	apiURL := os.Getenv("API_URL")
	transparencyEnv := os.Getenv("TRANSPARENCY_ENV")
	oidcIssuerRegex := os.Getenv("TRANSPARENCY_OIDC_ISSUER_REGEX")
	oidcSubjectRegex := os.Getenv("TRANSPARENCY_OIDC_SUBJECT_REGEX")

	client, err := openai.NewClient(t.Context(), apiKey, apiURL,
		openpcc.WithTransparencyEnvironment(transparencyEnv),
		openpcc.WithTransparencyOIDCIssuerRegex(oidcIssuerRegex),
		openpcc.WithTransparencyOIDCSubjectRegex(oidcSubjectRegex),
		openpcc.WithNodeTags([]string{"llm", "model=" + model}),
	)
	require.NoError(t, err)

	t.Cleanup(func() {
		err := client.Close(t.Context())
		require.NoError(t, err)
	})

	completion, err := client.Chat.Completions.New(t.Context(), origopenai.ChatCompletionNewParams{
		Messages: []origopenai.ChatCompletionMessageParamUnion{
			origopenai.UserMessage("Say this is a test"),
		},
		Model: model,
	})
	require.NoError(t, err)
	require.GreaterOrEqual(t, len(completion.Choices), 1)

	println(completion.Choices[0].Message.Content)
}
