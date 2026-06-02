package acme

import (
	"bytes"
	"context"
	"crypto"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
)

const (
	contentTypeJoseJSON = "application/jose+json"
	contentTypeProblem  = "application/problem+json"
)

type Client struct {
	DirectoryURL string
	Key          crypto.Signer
	HTTPClient   *http.Client

	dir     Directory
	kid     string
	nonce   string
	dirRead bool
}

func NewClient(directoryURL string, key crypto.Signer) *Client {
	return &Client{
		DirectoryURL: directoryURL,
		Key:          key,
	}
}

func (c *Client) Discover(ctx context.Context) (Directory, error) {
	if strings.TrimSpace(c.DirectoryURL) == "" {
		return Directory{}, errors.New("directory url is empty")
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.DirectoryURL, nil)
	if err != nil {
		return Directory{}, fmt.Errorf("create directory request: %w", err)
	}

	var dir Directory
	resp, err := c.httpClient().Do(req)
	if err != nil {
		return Directory{}, fmt.Errorf("get directory: %w", err)
	}
	defer closeBody(resp.Body)

	if err := decodeACMEResponse(resp, http.StatusOK, &dir); err != nil {
		return Directory{}, err
	}
	if dir.NewNonce == "" || dir.NewAccount == "" || dir.NewOrder == "" {
		return Directory{}, errors.New("directory missing required endpoints")
	}

	c.dir = dir
	c.dirRead = true
	return dir, nil
}

func (c *Client) NewAccount(ctx context.Context, req AccountRequest) (Account, error) {
	dir, err := c.directory(ctx)
	if err != nil {
		return Account{}, err
	}

	var account Account
	resp, err := c.post(ctx, dir.NewAccount, "", req, &account, http.StatusCreated, http.StatusOK)
	if err != nil {
		return Account{}, err
	}

	loc := resp.Header.Get("Location")
	if loc == "" {
		return Account{}, errors.New("new account response missing Location")
	}
	c.kid = loc
	return account, nil
}

func (c *Client) AccountURL() string {
	return c.kid
}

func (c *Client) SetAccountURL(kid string) {
	c.kid = kid
}

func (c *Client) NewOrder(ctx context.Context, domains []string) (Order, error) {
	if len(domains) == 0 {
		return Order{}, errors.New("order requires at least one domain")
	}

	identifiers := make([]Identifier, 0, len(domains))
	for _, domain := range domains {
		domain = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(domain)), ".")
		if domain == "" {
			return Order{}, errors.New("order contains empty domain")
		}
		identifiers = append(identifiers, Identifier{Type: "dns", Value: domain})
	}

	return c.NewOrderRequest(ctx, OrderRequest{Identifiers: identifiers})
}

func (c *Client) NewOrderRequest(ctx context.Context, req OrderRequest) (Order, error) {
	if c.kid == "" {
		return Order{}, errors.New("account url is empty")
	}
	dir, err := c.directory(ctx)
	if err != nil {
		return Order{}, err
	}

	var order Order
	resp, err := c.post(ctx, dir.NewOrder, c.kid, req, &order, http.StatusCreated)
	if err != nil {
		return Order{}, err
	}
	order.Location = resp.Header.Get("Location")
	return order, nil
}

func (c *Client) GetAuthorization(ctx context.Context, url string) (Authorization, error) {
	if c.kid == "" {
		return Authorization{}, errors.New("account url is empty")
	}

	var auth Authorization
	resp, err := c.postAsGet(ctx, url, &auth, http.StatusOK)
	if err != nil {
		return Authorization{}, err
	}
	auth.Location = resp.Header.Get("Location")
	if auth.Location == "" {
		auth.Location = url
	}
	return auth, nil
}

func (c *Client) AcceptChallenge(ctx context.Context, challengeURL string) (Challenge, error) {
	if c.kid == "" {
		return Challenge{}, errors.New("account url is empty")
	}

	var challenge Challenge
	_, err := c.post(ctx, challengeURL, c.kid, struct{}{}, &challenge, http.StatusOK)
	return challenge, err
}

func (c *Client) FinalizeOrder(ctx context.Context, finalizeURL string, csrDER []byte) (Order, error) {
	if c.kid == "" {
		return Order{}, errors.New("account url is empty")
	}
	if len(csrDER) == 0 {
		return Order{}, errors.New("csr is empty")
	}

	req := FinalizeRequest{CSR: rawURLEncoding.EncodeToString(csrDER)}
	var order Order
	resp, err := c.post(ctx, finalizeURL, c.kid, req, &order, http.StatusOK)
	if err != nil {
		return Order{}, err
	}
	order.Location = resp.Header.Get("Location")
	return order, nil
}

func (c *Client) FinalizeOrderCSR(ctx context.Context, finalizeURL string, csr *x509.CertificateRequest) (Order, error) {
	if csr == nil {
		return Order{}, errors.New("csr is nil")
	}
	return c.FinalizeOrder(ctx, finalizeURL, csr.Raw)
}

func (c *Client) GetOrder(ctx context.Context, orderURL string) (Order, error) {
	if c.kid == "" {
		return Order{}, errors.New("account url is empty")
	}

	var order Order
	resp, err := c.postAsGet(ctx, orderURL, &order, http.StatusOK)
	if err != nil {
		return Order{}, err
	}
	order.Location = resp.Header.Get("Location")
	if order.Location == "" {
		order.Location = orderURL
	}
	return order, nil
}

func (c *Client) GetCertificate(ctx context.Context, certificateURL string) ([]byte, error) {
	if c.kid == "" {
		return nil, errors.New("account url is empty")
	}

	resp, err := c.postRaw(ctx, certificateURL, c.kid, nil)
	if err != nil {
		return nil, err
	}
	defer closeBody(resp.Body)

	if err := expectStatus(resp, http.StatusOK); err != nil {
		return nil, err
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read certificate response: %w", err)
	}
	return body, nil
}

func (c *Client) directory(ctx context.Context) (Directory, error) {
	if c.dirRead {
		return c.dir, nil
	}
	return c.Discover(ctx)
}

func (c *Client) getNonce(ctx context.Context) (string, error) {
	if c.nonce != "" {
		nonce := c.nonce
		c.nonce = ""
		return nonce, nil
	}

	dir, err := c.directory(ctx)
	if err != nil {
		return "", err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodHead, dir.NewNonce, nil)
	if err != nil {
		return "", fmt.Errorf("create nonce request: %w", err)
	}
	resp, err := c.httpClient().Do(req)
	if err != nil {
		return "", fmt.Errorf("get nonce: %w", err)
	}
	defer closeBody(resp.Body)

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		return "", responseError(resp)
	}
	nonce := resp.Header.Get("Replay-Nonce")
	if nonce == "" {
		return "", errors.New("nonce response missing Replay-Nonce")
	}
	return nonce, nil
}

func (c *Client) postAsGet(ctx context.Context, url string, out any, okStatuses ...int) (*http.Response, error) {
	return c.postRawDecode(ctx, url, c.kid, nil, out, okStatuses...)
}

func (c *Client) post(ctx context.Context, url string, kid string, payload any, out any, okStatuses ...int) (*http.Response, error) {
	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("marshal acme payload: %w", err)
	}
	return c.postRawDecode(ctx, url, kid, payloadJSON, out, okStatuses...)
}

func (c *Client) postRawDecode(ctx context.Context, url string, kid string, payload []byte, out any, okStatuses ...int) (*http.Response, error) {
	resp, err := c.postRaw(ctx, url, kid, payload)
	if err != nil {
		return nil, err
	}
	defer closeBody(resp.Body)

	if err := decodeACMEResponse(resp, okStatuses[0], out, okStatuses[1:]...); err != nil {
		return nil, err
	}
	return resp, nil
}

func (c *Client) postRaw(ctx context.Context, url string, kid string, payload []byte) (*http.Response, error) {
	nonce, err := c.getNonce(ctx)
	if err != nil {
		return nil, err
	}

	body, err := makeJWS(c.Key, kid, nonce, url, payload)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("create acme post request: %w", err)
	}
	req.Header.Set("Content-Type", contentTypeJoseJSON)

	resp, err := c.httpClient().Do(req)
	if err != nil {
		return nil, fmt.Errorf("post acme request: %w", err)
	}
	if next := resp.Header.Get("Replay-Nonce"); next != "" {
		c.nonce = next
	}
	return resp, nil
}

func (c *Client) httpClient() *http.Client {
	if c.HTTPClient != nil {
		return c.HTTPClient
	}
	return http.DefaultClient
}

func decodeACMEResponse(resp *http.Response, firstOK int, out any, moreOK ...int) error {
	if err := expectStatus(resp, append([]int{firstOK}, moreOK...)...); err != nil {
		return err
	}
	if out == nil {
		return nil
	}
	if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
		return fmt.Errorf("decode acme response: %w", err)
	}
	return nil
}

func expectStatus(resp *http.Response, okStatuses ...int) error {
	for _, status := range okStatuses {
		if resp.StatusCode == status {
			return nil
		}
	}
	return responseError(resp)
}

func responseError(resp *http.Response) error {
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if strings.Contains(resp.Header.Get("Content-Type"), contentTypeProblem) {
		var problem Problem
		if err := json.Unmarshal(body, &problem); err == nil && (problem.Type != "" || problem.Detail != "") {
			return fmt.Errorf("acme problem %s: %s", problem.Type, problem.Detail)
		}
	}
	return fmt.Errorf("acme response status %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
}

func closeBody(body io.Closer) {
	_ = body.Close()
}
