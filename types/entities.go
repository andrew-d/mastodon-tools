package types

// https://docs.joinmastodon.org/entities/DomainBlock/
type DomainBlock struct {
	Domain   string `json:"domain"`
	Digest   string `json:"digest"`
	Severity string `json:"severity"`
	Comment  string `json:"comment"`
}
