package helpers

import "net/http"

// MastodonTransport is a http.RoundTripper that adds the Authorization and
// User-Agent header to outgoing requests to the provided Domain.
type MastodonTransport struct {
	// Domain is the domain of the Mastodon server.
	Domain string

	// Token is the Bearer token to add to the request.
	Token string

	// UserAgent, if non-empty, is the User-Agent header to add to
	// outgoing requests.
	UserAgent string

	// Inner is the underlying http.RoundTripper to use to make requests.
	Inner http.RoundTripper
}

func (tp *MastodonTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.URL.Hostname() == tp.Domain {
		req.Header.Add("Authorization", "Bearer "+tp.Token)
		if tp.UserAgent != "" {
			req.Header.Set("User-Agent", tp.UserAgent)
		}
	}
	return tp.Inner.RoundTrip(req)
}
