package types

// https://docs.joinmastodon.org/entities/DomainBlock/
type DomainBlock struct {
	Domain   string `json:"domain"`
	Digest   string `json:"digest"`
	Severity string `json:"severity"`
	Comment  string `json:"comment"`
}

// https://docs.joinmastodon.org/entities/Account/#CredentialAccount
type CredentialAccount struct {
	ID           string `json:"id"`
	Username     string
	WebfingerURI string `json:"acct"`
	DisplayName  string `json:"display_name"`
	Role         Role   `json:"role"`
}

// https://docs.joinmastodon.org/entities/Role/
type Role struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Color       string `json:"color"`
	Permissions string `json:"permissions"`
	Highlighted bool   `json:"highlighted"`
}
