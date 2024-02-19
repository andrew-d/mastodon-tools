package helpers

import (
	"context"
	"net/http"
	"strconv"
	"time"
)

// RateLimit sleeps so that requests to Mastodon don't exceed the returned rate
// limit, or until the provided context is cancelled. It will attempt to leave
// at least 'buffer' requests in the rate limit so as not to lock the user out
// of their account.
func RateLimit(ctx context.Context, resp *http.Response, buffer int) error {
	remaining, err := strconv.Atoi(resp.Header.Get("X-RateLimit-Remaining"))
	if err != nil {
		return nil // non-fatal
	}

	if remaining > buffer {
		return nil // no sleep needed
	}

	// Parse remaining time
	reset, err := time.Parse(time.RFC3339Nano, resp.Header.Get("X-Ratelimit-Reset"))
	if err != nil {
		return nil // non-fatal
	}

	// Sleep until that time, or until the context is exceeded.
	dur := reset.Sub(time.Now())
	timer := time.NewTimer(dur)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}
