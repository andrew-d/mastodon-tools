package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/andrew-d/mastodon-tools/helpers"
	"github.com/andrew-d/mastodon-tools/types"
	"go4.org/netipx"
)

var scopes = []string{
	types.ScopeAdminRead,
	types.ScopeAdminWrite,
	types.ScopeRead,
}

var (
	verbose      = flag.Bool("verbose", false, "print verbose log messages")
	dryRun       = flag.Bool("dry-run", false, "print what would be done without making changes")
	remove       = flag.Bool("remove", false, "if true, remove all rules that are managed by this tool without adding any")
	domain       = flag.String("domain", "", "local domain")
	clientID     = flag.String("client-id", "", "Mastodon client ID")
	clientSecret = flag.String("client-secret", "", "Mastodon client secret")
	prefix       = flag.String("prefix", "ipblock:", "prefix added to the comment on IP blocks to indicate that they're managed by this tool")

	// One of the following must be specified
	remoteURL = flag.String("url", "", "a URL to a list of IP addresses to block")
	file      = flag.String("file", "", "a file containing a list of IP addresses to block, one per line")
)

func main() {
	flag.Parse()
	log.SetOutput(os.Stderr)

	if *remoteURL == "" && *file == "" {
		log.Fatal("either --url or --file must be specified")
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// For now, we always use interactive authentication.
	code, err := getAuthCode(*domain)
	if err != nil {
		log.Fatalf("error getting auth code: %v", err)
	}
	token, err := helpers.GetBearerToken(ctx, http.DefaultClient, &helpers.GetBearerTokenOpts{
		Domain:       *domain,
		ClientID:     *clientID,
		ClientSecret: *clientSecret,
		Code:         code,
	})
	if err != nil {
		log.Fatalf("error getting auth token: %v", err)
	}

	httpc := &http.Client{
		Transport: &helpers.MastodonTransport{
			Domain:    *domain,
			Token:     token,
			UserAgent: "block-ips/0.0.1",
			Inner:     http.DefaultTransport,
		},
	}

	if err := helpers.VerifyCredentials(ctx, httpc, *domain); err != nil {
		log.Fatalf("error verifying credentials: %v", err)
	}

	// Fetching all data from our server and the remote location shouldn't take more than about 10s
	fetchCtx, fetchCancel := context.WithTimeout(ctx, 10*time.Second)
	defer fetchCancel()

	// Fetch all existing IP blocks
	var blocks []*types.AdminIPBlock
	err = helpers.Depaginate(
		fetchCtx,
		"https://"+*domain+"/api/v1/admin/ip_blocks",
		func(ctx context.Context, url string) (*http.Response, error) {
			req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
			if err != nil {
				return nil, err
			}
			return httpc.Do(req)
		},
		func(body []byte) error {
			page, err := decodeSliceBytes[*types.AdminIPBlock](body)
			if err != nil {
				return err
			}
			blocks = append(blocks, page...)
			return nil
		},
	)
	if err != nil {
		log.Fatalf("error fetching IP blocks: %v", err)
	}

	// In order to make changes to this Mastodon instance, we do a few
	// things which will be explained here in one spot:
	//	1. Parse the blocks we just retrieved from the instance into Go
	//	   netip.Prefix types, and segment them into blocks managed by
	//	   this tool and blocks that are managed by something else.
	//	2. Fetch all remote IPs.
	//	3. Remove things from the list of remote IPs that are covered
	//	   by rules that aren't managed by us; this could be because a
	//	   broader prefix has been blocked, or because the instance
	//	   admin(s) want to provide more details in a comment, or
	//	   whatever.
	//	4. Given the list of actually-missing IP blocks from our remote
	//	   list, construct our expected set of blocks (in the same
	//	   format as was generated in step #1).
	//	5. Diff the two lists and add/remove from the instance as
	//	   necessary to true everything up.

	// Parse into IP prefixes so we can test below.
	type ipBlock struct {
		Prefix   netip.Prefix
		Comment  string
		Severity string
	}
	var (
		ipBlocks   []ipBlock
		blocksInfo = make(map[ipBlock]*types.AdminIPBlock) // for deleting, so we can look up the ID
	)
	for _, block := range blocks {
		pfx, err := netip.ParsePrefix(block.IP)
		if err != nil {
			log.Printf("invalid prefix %q: %v", block.IP, err)
			continue
		}
		new := ipBlock{
			Prefix:   pfx,
			Comment:  block.Comment,
			Severity: block.Severity,
		}
		ipBlocks = append(ipBlocks, new)
		blocksInfo[new] = block
	}
	slices.SortFunc(ipBlocks, func(a, b ipBlock) int {
		return netipx.ComparePrefix(a.Prefix, b.Prefix)
	})
	log.Printf("got %d ip blocks", len(ipBlocks))

	// Segment into block managed by this tool and "others".
	var ours, others []ipBlock
	for _, block := range ipBlocks {
		if strings.HasPrefix(block.Comment, *prefix) {
			ours = append(ours, block)
		} else {
			others = append(others, block)
		}
	}

	// Fetch all IPs to block from the remote
	remoteIPs, err := getRemoteIPsToBlock(fetchCtx, httpc)
	if err != nil {
		log.Fatalf("error fetching IPs to block: %v", err)
	}
	log.Printf("got %d IPs to block", len(remoteIPs))

	// Remove all remote IPs that are covered by a rule that we're not
	// managing; we just ignore those entirely.
	//
	// TODO: this is O(n^2); we could do something better
	var missing []netip.Addr
	for _, ip := range remoteIPs {
		found := false
		for _, block := range others {
			if block.Prefix.Contains(ip) {
				found = true
				break
			}
		}
		if found {
			dlogf("already blocking IP: %v", ip)
			continue
		}

		missing = append(missing, ip)
	}
	log.Printf("missing IP blocks for %d IPs", len(missing))

	// TODO: we should perform some sort of "route summarization" algorithm
	// where we collapse adjacent IPs into a single prefix, rather than add
	// a bunch of /32s

	// Now that we have a list of missing exit nodes, construct our expected list of blocks.
	var expected []ipBlock
	for _, ip := range missing {
		pfx := netip.PrefixFrom(ip, 32)

		expected = append(expected, ipBlock{
			Prefix:   pfx,
			Comment:  *prefix + getRemoteKey(pfx),
			Severity: types.IPBlockSeverityRequiresApproval, // TODO: configurable
		})
	}

	// Okay, finally done; walk through our list of rules and remove/add things as necessary.
	_, err = helpers.Diff(ours, expected, func(block ipBlock) error {
		if *remove {
			return nil // do not add anything
		}

		log.Printf("adding IP block to instance: %v", block)
		if *dryRun {
			return nil // do nothing
		}

		// Each individual request shouldn't take more than a few seconds.
		ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()

		return addIPBlock(ctx, httpc, *domain, block.Prefix, block.Severity, block.Comment)
	}, func(block ipBlock) error {
		existingBlock := blocksInfo[block]
		log.Printf("deleting IP block: %v with ID %q", block, existingBlock.ID)
		if *dryRun {
			return nil // do nothing
		}

		// As above
		ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		return deleteIPBlock(ctx, httpc, *domain, existingBlock.ID)
	})
	if err != nil {
		log.Fatalf("error modifying IP blocks: %v", err)
	}
	log.Printf("successfully synchronized IP blocks")
}

// getRemoteKey returns a unique key for a given netip.Prefix, used to help
// match given IPs across runs of this tool.
func getRemoteKey(pfx netip.Prefix) string {
	// TODO(andrew-d): should this hash anything other than the prefix?
	// e.g. the source of the prefix?
	key := fmt.Sprintf("%s\x00", pfx)
	hash := sha256.Sum256([]byte(key))
	return hex.EncodeToString(hash[:])[:16]
}

func getRemoteIPsToBlock(ctx context.Context, httpc *http.Client) ([]netip.Addr, error) {
	var body []byte
	if *remoteURL != "" {
		req, err := http.NewRequestWithContext(ctx, "GET", *remoteURL, nil)
		if err != nil {
			return nil, fmt.Errorf("creating request: %w", err)
		}

		resp, err := httpc.Do(req)
		if err != nil {
			return nil, fmt.Errorf("fetching remote IPs: %w", err)
		}
		defer resp.Body.Close()

		body, err = io.ReadAll(resp.Body)
		if err != nil {
			return nil, fmt.Errorf("reading response body: %w", err)
		}
	} else {
		var err error
		body, err = os.ReadFile(*file)
		if err != nil {
			return nil, fmt.Errorf("reading file: %w", err)
		}
	}

	var ret []netip.Addr
	for _, ip := range strings.Split(strings.TrimSpace(string(body)), "\n") {
		if addr, err := netip.ParseAddr(ip); err == nil {
			ret = append(ret, addr)
		}
	}
	return ret, nil
}

const limitBuffer = 100 // never go below this many remaining requests

func addIPBlock(ctx context.Context, httpc *http.Client, domain string, ip netip.Prefix, severity string, comment string) error {
	params := url.Values{
		"ip":         {ip.String()},
		"severity":   {severity},
		"comment":    {comment},
		"expires_in": {strconv.Itoa(3 * 31_536_000)}, // 3 years, ignoring leap years
	}

	req, err := http.NewRequestWithContext(ctx, "POST", "https://"+domain+"/api/v1/admin/ip_blocks", strings.NewReader(params.Encode()))
	if err != nil {
		return fmt.Errorf("constructing request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := httpc.Do(req)
	if err != nil {
		return fmt.Errorf("making IP block request: %w", err)
	}
	defer resp.Body.Close()

	// TODO: put in a better spot?
	if err := helpers.RateLimit(ctx, dlogf, resp, limitBuffer); err != nil {
		return fmt.Errorf("waiting for rate limit: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("bad response code: %d", resp.StatusCode)
	}

	return nil
}

func deleteIPBlock(ctx context.Context, httpc *http.Client, domain, id string) error {
	uri := "https://" + domain + "/api/v1/admin/ip_blocks/" + id
	req, err := http.NewRequestWithContext(ctx, "DELETE", uri, nil)
	if err != nil {
		return fmt.Errorf("constructing request: %w", err)
	}
	resp, err := httpc.Do(req)
	if err != nil {
		return fmt.Errorf("making delete IP block request: %w", err)
	}
	defer resp.Body.Close()

	// TODO: put in a better spot?
	if err := helpers.RateLimit(ctx, dlogf, resp, limitBuffer); err != nil {
		return fmt.Errorf("waiting for rate limit: %w", err)
	}

	// 404 not found is okay when deleting
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNotFound {
		return fmt.Errorf("bad response code: %d", resp.StatusCode)
	}

	return nil
}

func decodeSliceBytes[T any](b []byte) ([]T, error) {
	var zero, ret []T
	if err := json.Unmarshal(b, &ret); err != nil {
		return zero, err
	}
	return ret, nil
}

func getAuthCode(domain string) (string, error) {
	// Start by asking the user to authenticate.
	log.Printf("please visit the auth url: %s", helpers.AuthCodeURL(
		domain, *clientID, scopes,
	))

	fmt.Fprint(os.Stderr, "enter authentication code: ")
	var authCode string
	if _, err := fmt.Scanln(&authCode); err != nil {
		return "", fmt.Errorf("reading authentication code: %w", err)
	}

	authCode = strings.TrimSpace(authCode)
	if authCode == "" {
		return "", fmt.Errorf("no authentication code provided")
	}
	return authCode, nil
}

func dlogf(format string, args ...any) {
	if !*verbose {
		return
	}
	log.Printf(format, args...)
}
