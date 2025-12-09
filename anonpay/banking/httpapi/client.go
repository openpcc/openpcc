package httpapi

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/cenkalti/backoff/v4"
	"github.com/openpcc/openpcc/anonpay"
	"github.com/openpcc/openpcc/anonpay/banking"
	anonpaypb "github.com/openpcc/openpcc/gen/protos/anonpay"
	pb "github.com/openpcc/openpcc/gen/protos/anonpay/banking"
	"github.com/openpcc/openpcc/httpretry"
	"github.com/openpcc/openpcc/otel/otelutil"
	"github.com/openpcc/openpcc/proton"
	"go.opentelemetry.io/otel/attribute"
	"google.golang.org/protobuf/proto"
)

type HTTPClient interface {
	Do(req *http.Request) (*http.Response, error)
}

type BackoffFunc func() backoff.BackOff

type Client struct {
	bankURL        string
	httpClient     HTTPClient
	reqBackoffFunc BackoffFunc
}

func NewClient(httpClient HTTPClient, bankURL string) (*Client, error) {
	return NewClientWithBackoff(httpClient, bankURL, func() backoff.BackOff {
		return backoff.NewExponentialBackOff(
			backoff.WithMaxElapsedTime(3 * time.Minute),
		)
	})
}

func NewClientWithBackoff(httpClient HTTPClient, bankURL string, backoffFunc BackoffFunc) (*Client, error) {
	return &Client{
		bankURL:        bankURL,
		httpClient:     httpClient,
		reqBackoffFunc: backoffFunc,
	}, nil
}

func (c *Client) WithdrawBatch(ctx context.Context, transferID []byte, account banking.AccountToken, reqs []anonpay.BlindSignRequest) (int64, [][]byte, error) {
	ctx, span := otelutil.Tracer.Start(ctx, "anonpay.banking.httpapi.Client.WithdrawBatch")
	span.SetAttributes(attribute.String("transfer_id", hex.EncodeToString(transferID)))
	defer span.End()

	reqPBs := make([]*anonpaypb.BlindSignRequest, len(reqs))
	for i, req := range reqs {
		valuePB, err := req.Value.MarshalProto()
		if err != nil {
			return 0, nil, fmt.Errorf("failed to marshal amount to protobuf: %w", err)
		}
		reqPBs[i] = anonpaypb.BlindSignRequest_builder{
			Value:          valuePB,
			BlindedMessage: req.BlindedMessage,
		}.Build()
	}

	batchPB := pb.BatchWithdrawRequest_builder{
		Requests:     reqPBs,
		AccountToken: account.SecretBytes(),
	}.Build()

	resp := pb.BatchWithdrawResponse{}
	err := c.doRequest(ctx, "/withdraw", batchPB, &resp)
	if err != nil {
		return 0, nil, otelutil.Errorf(span, "failed to withdraw batch: %w", err)
	}

	blindSigs := resp.GetBlindSignatures()
	if len(blindSigs) != len(reqs) {
		return 0, nil, otelutil.Errorf(span, "need %d blind signatures, but got %d in response", len(reqs), len(blindSigs))
	}

	return resp.GetBalance(), blindSigs, nil
}

func (c *Client) WithdrawFullUnblinded(ctx context.Context, transferID []byte, account banking.AccountToken) (*anonpay.UnblindedCredit, error) {
	ctx, span := otelutil.Tracer.Start(ctx, "anonpay.banking.httpapi.Client.WithdrawFullUnblinded")
	span.SetAttributes(attribute.String("transfer_id", hex.EncodeToString(transferID)))
	defer span.End()

	// Take all the money out of an account
	req := pb.WithdrawFullUnblindedRequest_builder{
		AccountToken: account.SecretBytes(),
	}.Build()

	resp := pb.WithdrawFullUnblindedResponse{}
	err := c.doRequest(ctx, "/withdraw-full", req, &resp)
	if err != nil {
		return nil, otelutil.Errorf(span, "failed to withdraw all: %w", err)
	}

	credit := &anonpay.UnblindedCredit{}
	if err := credit.UnmarshalProto(resp.GetCredit()); err != nil {
		return nil, otelutil.Errorf(span, "error unmarshalling withdraw all credit: %w", err)
	}

	return credit, nil
}

func (c *Client) Deposit(ctx context.Context, transferID []byte, account banking.AccountToken, credit *anonpay.BlindedCredit) (int64, error) {
	ctx, span := otelutil.Tracer.Start(ctx, "anonpay.banking.httpapi.Client.Deposit")
	span.SetAttributes(attribute.String("transfer_id", hex.EncodeToString(transferID)))
	defer span.End()

	pc, err := credit.MarshalProto()
	if err != nil {
		return 0, otelutil.Errorf(span, "error marshalling credit: %w", err)
	}
	req := pb.DepositRequest_builder{
		AccountToken: account.SecretBytes(),
		Credit:       pc,
	}.Build()
	resp := pb.DepositResponse{}
	err = c.doRequest(ctx, "/deposit", req, &resp)
	if err != nil {
		return 0, otelutil.Errorf(span, "failed to deposit: %w", err)
	}

	return resp.GetBalance(), nil
}

func (c *Client) Exchange(ctx context.Context, transferID []byte, credit anonpay.AnyCredit, request anonpay.BlindSignRequest) ([]byte, error) {
	ctx, span := otelutil.Tracer.Start(ctx, "anonpay.banking.httpapi.Client.Exchange")
	span.SetAttributes(attribute.String("transfer_id", hex.EncodeToString(transferID)))
	defer span.End()

	pc, err := credit.MarshalProto()
	if err != nil {
		return nil, otelutil.Errorf(span, "failed to marshal credit to protobuf: %w", err)
	}

	req := pb.ExchangeRequest_builder{
		Credit:         pc,
		BlindedMessage: request.BlindedMessage,
	}.Build()
	resp := pb.ExchangeResponse{}
	err = c.doRequest(ctx, "/exchange", req, &resp)
	if err != nil {
		return nil, otelutil.Errorf(span, "failed to exchange: %w", err)
	}

	return resp.GetBlindSignature(), nil
}

func (c *Client) Balance(ctx context.Context, account banking.AccountToken) (int64, error) {
	ctx, span := otelutil.Tracer.Start(ctx, "anonpay.banking.httpapi.Client.Exchange")
	defer span.End()

	req := pb.BalanceRequest_builder{
		AccountToken: account.SecretBytes(),
	}.Build()
	resp := pb.BalanceResponse{}
	err := c.doRequest(ctx, "/balance", req, &resp)
	if err != nil {
		return 0, otelutil.Errorf(span, "failed to exchange: %w", err)
	}

	return resp.GetBalance(), nil
}

func (c *Client) doRequest(ctx context.Context, endpoint string, reqPB proto.Message, outPB proto.Message) error {
	reqBytes, err := proto.Marshal(reqPB)
	if err != nil {
		return fmt.Errorf("failed to marshal request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.bankURL+endpoint, bytes.NewReader(reqBytes))
	req.Header.Set("Content-Type", "application/octet-stream")
	if err != nil {
		return fmt.Errorf("failed to create http request: %w", err)
	}

	resp, err := httpretry.DoWith(c.httpClient, req, c.reqBackoffFunc(), httpretry.Retry5xx)
	if err != nil {
		return fmt.Errorf("http request failed: %w", err)
	}
	defer func() {
		closeErr := resp.Body.Close()
		err = errors.Join(err, closeErr)
	}()

	if resp.StatusCode != http.StatusOK {
		err = fmt.Errorf("unexpected status code from blind bank: %d for %s", resp.StatusCode, endpoint)
		if resp.StatusCode == http.StatusBadRequest {
			return anonpay.InputError{
				Err: err,
			}
		}
		return err
	}

	decoder := proton.NewDecoder(resp.Body)
	if err := decoder.Decode(outPB); err != nil {
		return fmt.Errorf("failed to decode response: %w", err)
	}

	return nil
}
