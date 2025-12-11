# OpenPCC OpenAI compatible client

This package contains an OpenAI client that routes requests via an OpenPCC client to make secure and anonymous AI inference requests.

This embeds the [official OpenAI Go client](https://github.com/openai/openai-go), so it can be used as a drop-in replacement.

However there is one important caveat: Unlike the official OpenAI Client, the client in this package needs to
be closed after use to clean up resources. Failure to close the client can result in lost (potentially already billed) anonymous credits.

## Installation

First, `go get` the openpcc package:

```sh
go get -u github.com/openpcc/openpcc
```

The OpenAI compatible client is located in the `openai` package in the above module. Import it using:

```go
import (
    "github.com/openpcc/openpcc/openai"
)
```

## Quickstart

First, configure the client to use your API key, the OpenPCC service API URL and the identity of the organization providing the OpenPCC service.

> The identity is important, because the OpenPCC client will only trust keys and compute nodes if it
> can verify that this identity signed and published them to a public append-only transparency log.

In the example below we require the OpenPCC client to only accept keys and compute nodes signed and published by the `release` workflow on the `main` branch in the `myorg/openpcc` repository on Github.

```go
import (
    "os"
    "context"
    origopenai "github.com/openai/openai-go/v3"
	"github.com/openpcc/openpcc"
	"github.com/openpcc/openpcc/openai"
)

func main() {
	ctx := context.Background()

	// credentials and OpenPCC API URL
	apiKey := os.Getenv("API_KEY")
	apiURL := os.Getenv("API_URL")

	// transparency settings
	oidcIssuer := "https://token.actions.githubusercontent.com"
	oidcSubject := "^https://github.com/myorg/myrepo/.github/workflows/release.yml@refs/heads/main"

	// set up the client.
	client, err := openai.NewClient(ctx, apiKey, apiURL,
		openpcc.WithTransparencyOIDCIssuerRegex(oidcIssuer),
		openpcc.WithTransparencyOIDCSubjectRegex(oidcSubject),
	)
	if err != nil {
		// handle error
	}

	// important: clean up when done.
	defer func() {
		err := client.Close(ctx)
		if err != nil {
			// handle error
		}
	}()
}
```

The client is now ready to use. It can be used just like a regular OpenAI client:

```go
func main() {
    // ...

    // note: origopenai refers to the official openai package here.
	completion, err := client.Chat.Completions.New(t.Context(), origopenai.ChatCompletionNewParams{
		Messages: []origopenai.ChatCompletionMessageParamUnion{
			origopenai.UserMessage("Say this is a test"),
		},
		Model: model,
	})
}
```

If you need lower-level access, you can retrieve the original OpenPCC client as follows.

```go
func main() {
    // ...

    // retrieve the openpcc.Client
    opccClient := client.OpenPCCClient()

    // use it to, for example, to construct
    // a new http.Client that routes requests via the configured
    // OpenPCC service.
    //
    // (Possible because openpcc.Client implements http.RoundTripper).
    httpClient := &http.Client{
        Transport: opccClient,
        Timeout: 30*time.Second,
    }
}
```

## Further configuration

The OpenAI client in this package supports all options available to the `openpcc.Client`, for more information
see this page. (TODO).
