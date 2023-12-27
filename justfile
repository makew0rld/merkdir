version := `git describe --tags || true`
commit := `git rev-parse --verify HEAD`
date := `date -u`
builtby := "just"

build:
    go build -tags urfave_cli_no_docs \
    -ldflags="-X 'main.version={{version}}' -X 'main.commit={{commit}}' -X 'main.date={{date}}' -X 'main.builtBy={{builtby}}'"
