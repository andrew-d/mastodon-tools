all: (build "block-ips") (build "sync-blocks")

build command:
    go build ./cmd/{{ command }}
