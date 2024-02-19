package helpers

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/andrew-d/mastodon-tools/types"
)

// GetBearerTokenOpts contains options for the GetBearerToken function.
//
// One of the following sets of fields must be set:
//  1. Username & Password
//  2. Code
//  3. RefreshToken
type GetBearerTokenOpts struct {
	// Domain is the domain name of the instance to operate on. This field
	// is required.
	Domain string
	// ClientID is the Mastodon application client ID. This field is
	// required.
	ClientID string
	// ClientSecret is the Mastodon application client secret. This field
	// is required.
	ClientSecret string

	// Username is the Mastodon username to authenticate as. If set,
	// Password must be set.
	Username string
	// Password is the password for the 'Username' account.
	Password string

	// Code is the authentication token generated via the out-of-band flow
	// (i.e. that prompts the user to visit a page in their browser and
	// copy the token into the application).
	Code string

	// RefreshToken is an OAuth refresh token.
	// NOTE: currently untested
	RefreshToken string
}

// GetBearerToken obtains a bearer token for use when authenticating to
// Mastodon by exchanging some form of authentication datum(s) with the
// Mastodon server.
func GetBearerToken(ctx context.Context, httpc *http.Client, opts *GetBearerTokenOpts) (string, error) {
	// Common options
	params := url.Values{
		"client_id":     {opts.ClientID},
		"client_secret": {opts.ClientSecret},
		"redirect_uri":  {"urn:ietf:wg:oauth:2.0:oob"},
	}

	// Per-method options
	if opts.Username != "" && opts.Password != "" {
		params["grant_type"] = []string{"password"}
		params["username"] = []string{opts.Username}
		params["password"] = []string{opts.Password}
	} else if opts.Code != "" {
		params["grant_type"] = []string{"authorization_code"}
		params["code"] = []string{opts.Code}
	} else if opts.RefreshToken != "" {
		params["grant_type"] = []string{"refresh_token"}
		params["refresh_token"] = []string{opts.RefreshToken}
	} else {
		return "", fmt.Errorf("no credentials provided")
	}

	// Actually make the HTTP request.
	uri := "https://" + opts.Domain + "/oauth/token"
	req, err := http.NewRequestWithContext(ctx, "POST", uri, strings.NewReader(params.Encode()))
	if err != nil {
		return "", fmt.Errorf("constructing request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := httpc.Do(req)
	if err != nil {
		return "", fmt.Errorf("making token request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("bad OAuth response: %d", resp.StatusCode)
	}

	var res struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&res); err != nil {
		return "", fmt.Errorf("decoding response body: %w", err)
	}

	return res.AccessToken, nil
}

// AuthCodeURL returns the URL for a user to visit in order to obtain an OAuth
// authorization code (which can then be used in GetBearerTokenOpts.Code).
func AuthCodeURL(domain, clientID string, scopes []string) string {
	params := url.Values{
		"client_id":     {clientID},
		"response_type": {"code"},
		"redirect_uri":  {"urn:ietf:wg:oauth:2.0:oob"},
		"scope":         {strings.Join(scopes, " ")},
	}
	return "https://" + domain + "/oauth/authorize?" + params.Encode()
}

// VerifyCredentials calls the /api/v1/accounts/verify_credentials endpoint and
// verifies that it returns a valid response. This is helpful to ensure that
// the credentials (which must be injected in the http.Client) are valid.
func VerifyCredentials(ctx context.Context, httpc *http.Client, domain string) error {
	req, err := http.NewRequestWithContext(ctx, "GET", "https://"+domain+"/api/v1/accounts/verify_credentials", nil)
	if err != nil {
		return err
	}
	resp, err := httpc.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("invalid status code: %d", resp.StatusCode)
	}

	var acct types.CredentialAccount
	if err := json.NewDecoder(resp.Body).Decode(&acct); err != nil {
		return err
	}
	if acct.ID == "" || acct.Username == "" {
		return fmt.Errorf("unexpected empty ID or Username")
	}

	return nil
}
