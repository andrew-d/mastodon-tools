package main

import (
	"context"
	"crypto/sha256"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/tailscale/hujson"
	xmaps "golang.org/x/exp/maps"

	"github.com/andrew-d/mastodon-tools/helpers"
	"github.com/andrew-d/mastodon-tools/types"
)

var scopes = []string{
	types.ScopeAdminRead,
	types.ScopeAdminWrite,
	types.ScopeRead,
}

type Client struct {
	domain string
	client *http.Client
}

type ClientOpts struct {
	Username string
	Password string

	Code string

	RefreshToken string
}

func NewClient(ctx context.Context, domain, clientID, clientSecret string, opts *ClientOpts) (*Client, error) {
	client := new(http.Client)

	// Obtain an OAuth token
	params := url.Values{
		"client_id":     {clientID},
		"client_secret": {clientSecret},
		"redirect_uri":  {"urn:ietf:wg:oauth:2.0:oob"},
	}
	if opts.Username != "" && opts.Password != "" {
		dlogf("getting token with username/password")
		params["grant_type"] = []string{"password"}
		params["username"] = []string{opts.Username}
		params["password"] = []string{opts.Password}
	} else if opts.Code != "" {
		dlogf("getting token with authentication code")
		params["grant_type"] = []string{"authorization_code"}
		params["code"] = []string{opts.Code}
	} else if opts.RefreshToken != "" {
		dlogf("getting token with refresh token")
		params["grant_type"] = []string{"refresh_token"}
		params["refresh_token"] = []string{opts.RefreshToken}
	} else {
		return nil, fmt.Errorf("no credentials provided")
	}

	req, err := http.NewRequestWithContext(ctx, "POST", "https://"+domain+"/oauth/token", strings.NewReader(params.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("bad OAuth response: %d", resp.StatusCode)
	}

	var res struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&res); err != nil {
		return nil, err
	}

	ret := &Client{
		domain: domain,
		client: &http.Client{
			Transport: &helpers.MastodonTransport{
				Domain:    domain,
				Token:     res.AccessToken,
				UserAgent: "sync-blocks/0.0.1",
				Inner:     http.DefaultTransport,
			},
		},
	}
	return ret, nil
}

func (c *Client) url(path string) string {
	return "https://" + c.domain + path
}

func (c *Client) get(ctx context.Context, url string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return nil, fmt.Errorf("invalid response status: %d", resp.StatusCode)
	}
	return resp, nil
}

func decodeSlice[T any](r io.Reader) ([]T, error) {
	var zero, ret []T
	if err := json.NewDecoder(r).Decode(&ret); err != nil {
		return zero, err
	}
	return ret, nil
}

func decodeSliceBytes[T any](b []byte) ([]T, error) {
	var zero, ret []T
	if err := json.Unmarshal(b, &ret); err != nil {
		return zero, err
	}
	return ret, nil
}

func (c *Client) GetDomainBlocks(ctx context.Context) (ret []*types.AdminDomainBlock, _ error) {
	err := helpers.Depaginate(
		ctx,
		c.url("/api/v1/admin/domain_blocks"),
		c.get, // to fetch
		func(body []byte) error {
			page, err := decodeSliceBytes[*types.AdminDomainBlock](body)
			if err != nil {
				return err
			}
			ret = append(ret, page...)
			return nil
		})
	if err != nil {
		return nil, err
	}
	return ret, nil
}

func getCodeURL(domain, clientID string) string {
	params := url.Values{
		"client_id":     {clientID},
		"response_type": {"code"},
		"redirect_uri":  {"urn:ietf:wg:oauth:2.0:oob"},
		"scope":         {strings.Join(scopes, " ")},
	}
	return "https://" + domain + "/oauth/authorize?" + params.Encode()
}

func scrapeDomainBlocks(ctx context.Context, domain string) ([]*types.DomainBlock, error) {
	url := "https://" + domain + "/api/v1/instance/domain_blocks"
	resp, err := http.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return nil, fmt.Errorf("invalid response status: %d", resp.StatusCode)
	}
	return decodeSlice[*types.DomainBlock](resp.Body)
}

type Config struct {
	LocalInstance   string
	RemoteInstances []string
	MinInstances    int
	OnlyLimit       bool
	Exclusions      []string
	ClientID        string
	ClientSecret    string
	Auth            ConfigAuth
	BlockOptions    ConfigBlockOptions
}

type ConfigAuth struct {
	Code string

	PromptCode bool

	Username string
	Password string

	RefreshToken string
}

type ConfigBlockOptions struct {
	RejectMedia      bool
	RejectReports    bool
	SetPublicComment bool
	Obfuscate        bool
}

var (
	configPath = flag.String("config", "", "path to config file in JSON/HuJSON format")
	verbose    = flag.Bool("verbose", false, "print verbose log messages")
)

func main() {
	flag.Parse()
	log.SetOutput(os.Stderr)

	if *configPath == "" {
		log.Fatal("no config file specified")
	}
	var (
		configBytes []byte
		err         error
	)
	if *configPath == "-" {
		configBytes, err = io.ReadAll(os.Stdin)
	} else {
		configBytes, err = os.ReadFile(*configPath)
	}
	if err != nil {
		log.Fatalf("error reading config file %q: %v", *configPath, err)
	}

	var config Config
	configBytes, err = hujson.Standardize(configBytes)
	if err != nil {
		log.Fatalf("invalid HuJSON config file: %v", err)
	}
	if err := json.Unmarshal(configBytes, &config); err != nil {
		log.Fatalf("invalid config file: %v", err)
	}

	if config.LocalInstance == "" {
		log.Fatal("LocalInstance cannot be empty")
	}
	if len(config.RemoteInstances) == 0 {
		log.Fatal("no remote instances provided in RemoteInstances")
	}

	if config.MinInstances > len(config.RemoteInstances) {
		log.Fatalf("MinInstances is larger than the total number of remote instances %d", len(config.RemoteInstances))
	}

	haveExclusion := make(map[string]bool) // keyed by domain
	for _, s := range config.Exclusions {
		haveExclusion[s] = true
	}

	// Make client options for authentication
	opts, err := makeClientOpts(&config)
	if err != nil {
		log.Fatalf("error in authentication options: %v", err)
	}

	// Don't allow things to take more than 30 seconds.
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	c, err := NewClient(
		ctx,
		config.LocalInstance,
		config.ClientID,
		config.ClientSecret,
		opts,
	)
	if err != nil {
		log.Fatal(err)
	}

	adminBlocks, err := c.GetDomainBlocks(ctx)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("got %d domain blocks from local instance", len(adminBlocks))

	var (
		haveBlocks     = map[string]bool{}
		blocksByDigest = map[string]string{}
	)
	for _, block := range adminBlocks {
		haveBlocks[block.Domain] = true

		hash := sha256.Sum256([]byte(block.Domain))
		blocksByDigest[hex.EncodeToString(hash[:])] = block.Domain
	}

	instanceBlocks := make(map[string][]*types.DomainBlock) // keyed by remote instance domain
	blockCounts := make(map[string]int)                     // keyed by block.Domain
	for _, instance := range config.RemoteInstances {
		blocks, err := scrapeDomainBlocks(ctx, instance)
		if err != nil {
			log.Fatal("scraping domain blocks from instance %q: %v", instance, err)
		}
		// Remove any block with an asterisk in the domain; we don't
		// currently attempt to match this against other known blocks
		// to deobfuscate it.
		// TODO: do something better here
		blocks = slices.DeleteFunc(blocks, func(block *types.DomainBlock) bool {
			return strings.Contains(block.Domain, "*")
		})
		for _, block := range blocks {
			blockCounts[block.Domain]++
		}
		log.Printf("got %d domain blocks from instance %q", len(blocks), instance)
		instanceBlocks[instance] = blocks
	}

	// Collect all blocks that are greater than our threshold.
	blocksToApply := make(map[string]*types.DomainBlock) // keyed by block.Domain
	for instance, blocks := range instanceBlocks {
		for _, block := range blocks {
			if blockCounts[block.Domain] < config.MinInstances {
				continue
			}

			// If we don't have the block already, store it
			existing, found := blocksToApply[block.Domain]
			if !found {
				newBlock := &types.DomainBlock{
					Domain:   block.Domain,
					Digest:   block.Digest,
					Severity: block.Severity,
					Comment:  block.Comment,
				}
				blocksToApply[block.Domain] = newBlock
				continue
			}

			// We have it already; pick the larger severity
			switch {
			case config.OnlyLimit:
				// always overwrite, just to be safe
				existing.Severity = "silence"
			case existing.Severity == "suspend":
				// no change
			case existing.Severity == "silence" && block.Severity == "suspend":
				dlogf("upgrading block of domain %q to suspend from instance %q", block.Domain, instance)
			}

			// Append comment
			if block.Comment != "" {
				if existing.Comment != "" {
					existing.Comment += "; "
				}
				existing.Comment += block.Comment
			}
		}
	}

	// Sort the blocks by domain for consistent ordering.
	blockDomains := xmaps.Keys(blocksToApply)
	sort.Strings(blockDomains)

	rejectMedia := strconv.FormatBool(config.BlockOptions.RejectMedia)
	rejectReports := strconv.FormatBool(config.BlockOptions.RejectReports)
	obfuscate := strconv.FormatBool(config.BlockOptions.Obfuscate)

	// Find all instance blocks that we don't have.
	// TODO: apply to the local instance with the private comment set?
	csvW := csv.NewWriter(os.Stdout)
	csvW.Write([]string{"#domain", "#severity", "#reject_media", "#reject_reports", "#public_comment", "#obfuscate"})
	for _, blockDomain := range blockDomains {
		block := blocksToApply[blockDomain]

		// TODO: for both of these, check whether we have a parent
		// domain of this domain blocked; e.g. if the local instance
		// has "example.com" blocked, then we also have
		// "foo.example.com" blocked (and similar for exclusions).
		if haveBlocks[block.Domain] {
			continue
		}
		if haveExclusion[block.Domain] {
			log.Printf("not blocking excluded domain %q", block.Domain)
			continue
		}

		severity := block.Severity
		if config.OnlyLimit {
			severity = "silence"
		}

		comment := ""
		if config.BlockOptions.SetPublicComment {
			comment = block.Comment
		}

		dlogf("missing block: %s %q for reason: %q", severity, block.Domain, block.Comment)
		csvW.Write([]string{
			block.Domain,
			severity,
			rejectMedia,
			rejectReports,
			comment,
			obfuscate,
		})
	}
	csvW.Flush()
	if err := csvW.Error(); err != nil {
		log.Fatalf("writing CSV: %v", err)
	}
}

func makeClientOpts(config *Config) (*ClientOpts, error) {
	ao := config.Auth

	if ao.Username != "" && ao.Password != "" {
		return &ClientOpts{
			Username: ao.Username,
			Password: ao.Password,
		}, nil
	} else if ao.Code != "" {
		return &ClientOpts{Code: ao.Code}, nil
	} else if ao.RefreshToken != "" {
		return &ClientOpts{RefreshToken: ao.RefreshToken}, nil
	}

	if !ao.PromptCode {
		return nil, fmt.Errorf("no authentication credentials provided and PromptCode is false")
	}

	// Start by asking the user to authenticate.
	log.Printf("please visit the auth url: %s", getCodeURL(config.LocalInstance, config.ClientID))

	fmt.Fprint(os.Stderr, "enter authentication code: ")
	var authCode string
	if _, err := fmt.Scanln(&authCode); err != nil {
		return nil, fmt.Errorf("reading authentication code: %w", err)
	}

	authCode = strings.TrimSpace(authCode)
	if authCode == "" {
		return nil, fmt.Errorf("no authentication code provided")
	}
	return &ClientOpts{Code: authCode}, nil
}

func dlogf(format string, args ...any) {
	if !*verbose {
		return
	}
	log.Printf(format, args...)
}
