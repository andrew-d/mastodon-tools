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

## block-tor

This tool can be used to manage IP blocks (currently, hard-coded to the list of
Tor exit nodes). It will add and remove entries to the instance's list of IP
blocks based on a string prefix, essentially ensuring that the list of IP
blocks in Mastodon matches the set of IPs in the list it's parsing.

A future update will update the tool to allow synchronizing an arbitrary list
of IPs rather than just Tor exit nodes.

This tool currently only works interactively. An example of how to run it
(after creating a client ID and secret):

```bash
$ block-tor \
    -client-id 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' \
    -client-secret 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb' \
    -domain ottawa.place \
    -verbose
2024/02/19 00:01:02 got 12 ip blocks
2024/02/19 00:01:02 got 1234 Tor exit nodes
2024/02/19 00:01:02 already blocking IP: 1.2.3.4
2024/02/19 00:01:02 already blocking IP: 5.6.7.8
[...]
2024/02/19 00:14:48 missing IP blocks for 456 Tor exit nodes
2024/02/19 00:14:48 adding IP block to instance: {9.10.11.12/32 block-tor:eeeeeeeeeeeeeeee sign_up_requires_approval}
[...]
```

Note that you may have to run this multiple times on the first import; it has
some pretty aggressive timeouts, and while it tries to respect Mastodon's rate
limits, it's not perfect and does not currently retry appropriately. Also, if
it looks like it's hanging, it's probably just sleeping waiting for a rate
limit to reset. Sharp edges will be fixed in a future update!

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
