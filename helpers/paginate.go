// Package helpers contains some helpers for the Mastodon API.
package helpers

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"

	"github.com/peterhellberg/link"
)

// FetchPageFunc is the function that is called to fetch a given URL, and is
// responsible for adding any required authentication headers and making the
// HTTP request.
type FetchPageFunc func(ctx context.Context, url string) (*http.Response, error)

// ProcessPageFunc is called with the HTTP response body of each page.
type ProcessPageFunc func(body []byte) (err error)

// Depaginate calls a Mastodon API and iterates through all available pages,
// processing each one with the user-provided callback.
func Depaginate(ctx context.Context, startURL string, fetch FetchPageFunc, process ProcessPageFunc) error {
	const maxPageLimit = 500 // should never reach this
	currURL := startURL
	for i := 0; i < maxPageLimit; i++ {
		resp, err := fetch(ctx, currURL)
		if err != nil {
			return fmt.Errorf("fetching page %q: %w", currURL, err)
		}
		if resp.StatusCode < 200 || resp.StatusCode > 299 {
			return fmt.Errorf("invalid status code: %d", resp.StatusCode)
		}

		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			return fmt.Errorf("reading page %q body: %w", currURL, err)
		}

		if err := process(body); err != nil {
			return fmt.Errorf("processing page %q: %w", currURL, err)
		}

		lh := link.ParseResponse(resp)
		if uu, ok := lh["next"]; ok {
			currURL = uu.URI
		} else {
			// done
			return nil
		}
	}
	return errors.New("Depaginate: hit max page limit")
}
