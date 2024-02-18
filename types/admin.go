// Package types contains Go structures representing the Mastodon API types
package types

// https://docs.joinmastodon.org/entities/Admin_DomainBlock/
type AdminDomainBlock struct {
	ID             string `json:"id"`
	Domain         string `json:"domain"`
	CreatedAt      string `json:"created_at"`
	Severity       string `json:"severity"`
	RejectMedia    bool   `json:"reject_media"`
	RejectReports  bool   `json:"reject_reports"`
	PrivateComment string `json:"private_comment"`
	PublicComment  string `json:"public_comment"`
	Obfuscate      bool   `json:"obfuscate"`
}

// https://docs.joinmastodon.org/entities/Application/
type Application struct {
	Name         string  `json:"name"`
	Website      *string `json:"website"`
	ClientID     string  `json:"client_id"`
	ClientSecret string  `json:"client_secret"`
}
