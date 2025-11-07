# OpenPCC

OpenPCC is an open-source framework for provably private AI inference, inspired by Apple’s Private Cloud Compute but fully open, auditable, and deployable on your own infrastructure. It allows anyone to run open or custom AI models without exposing prompts, outputs, or logs - enforcing privacy with encrypted streaming, hardware attestation, and unlinkable requests.

OpenPCC is designed to become a transparent, community-governed standard for AI data privacy.

Read the OpenPCC Whitepaper: https://github.com/openpcc/openpcc/blob/main/whitepaper/openpcc.pdf

## Managed Service

Confident Security is building a fully managed service, called CONFSEC, based on the OpenPCC standard. To learn more and sign up, visit https://confident.security.

## OpenPCC Client

This repo contains the code for an OpenPCC compliant go client as well as a c library that is used as the basis of python and javascript clients. In addition, it contains a number of in-memory services that can be used to exercise the client.

## OpenPCC Compute Node

Refer to https://github.com/confidentsecurity/confidentcompute for the related compute node implementation that accompanies this repo.

### Go Usage

see cmd/test-client/main.go for a local dev example. To connect to a prod service, it would look something like this:

```go
import (
    "context"
    "fmt"
    "net/http"
    "os"
    "strings"

    "github.com/openpcc/openpcc"
    "github.com/openpcc/openpcc/inttest"
    "github.com/openpcc/openpcc/transparency"
)

func makePCCRequest() error {
    ctx := context.Background()

    identityPolicy := transparency.IdentityPolicy{
		OIDCSubjectRegex: "^https://github.com/confidentsecurity/T/.github/workflows.*",
		OIDCIssuerRegex:  "https://token.actions.githubusercontent.com",
    }

    cfg := openpcc.DefaultConfig()
    cfg.APIURL = "https://app.confident.security"
    cfg.APIKey = os.Getenv("<APIKEY_ENV_VAR_NAME>")
    cfg.TransparencyVerifier = transparency.DefaultVerifierConfig()
    cfg.TransparencyIdentityPolicy = &identityPolicy

    client, err := openpcc.NewFromConfig(ctx, cfg)
    if err != nil {
        return fmt.Errorf("failed to create openpcc client: %w", err)
    }

    // Inference requests use OpenAI API generate format
    body := "{\"model\":\"qwen3:1.7b\",\"prompt\":\"why is the sky blue?\"}"
    // nosemgrep: problem-based-packs.insecure-transport.go-stdlib.http-customized-request.http-customized-request
    req, err := http.NewRequest("POST", "http://confsec.invalid/v1/completions", strings.NewReader(body))
    if err != nil {
        return err
    }
    // add a tag to the request to route request to compute nodes that are running the specified model
    req.Header.Add("X-Confsec-Node-Tags", "qwen3:1.7b")

    resp, err := client.RoundTrip(req)
    if err != nil {
        return err
    }

    return nil
}
```

## Development

Dev commands are run using the go tool [`mage`](https://magefile.org)

you can run it just from the go.mod tool install with `go tool mage [cmd]`, or you can install mage itself to save the key presses: `go install github.com/magefile/mage@latest`

`mage` will print a list of commands (see /magefiles/* for the source of the commands)

To exercise the library in development, use `mage runMemServices` to run all the in-memory OpenPCC services. Then use `mage runClient` to make a test request into the system.
