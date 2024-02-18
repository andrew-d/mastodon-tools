## sync-blocks

This tool can be used to synchronize blocks from remote instance(s) to your
local instance, including options for only reporting blocks that at least M of
N remote servers have.

Currently it outputs a CSV file that must be manually imported into Mastodon;
in the future, this tool will support automatically adding blocks to the local
server so that it can be run on an automated basis.

The easiest way to test this out is to create a client ID and secret (see
below), copy the provided configuration file, and run it with "PromptCode" and
a set of servers to query.

## Creating a Mastodon Application

The tool(s) in this repository require a Mastodon client ID and secret to
operate. The easiest way to get this is, for a given domain:

```bash
$ curl \
    -F client_name=sync-blocks \
    -F 'redirect_uris=urn:ietf:wg:oauth:2.0:oob'
    -F 'scopes=admin:read admin:write read'
    -F 'website=https://github.com/andrew-d/mastodon-tools'
    https://MY.DOMAIN.COM/api/v1/apps | jq .
{
  "id": "1234",
  "name": "sync-blocks",
  "website": "https://github.com/andrew-d/mastodon-tools",
  "redirect_uri": "urn:ietf:wg:oauth:2.0:oob",
  "client_id": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
  "client_secret": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
  "vapid_key": "stuff"
}
```

For more details, see: https://docs.joinmastodon.org/client/token/
