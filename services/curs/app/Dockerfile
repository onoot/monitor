# The session store resolved by `go get` releases requiring a newer toolchain
# than this module's `go 1.22.2` directive, so the builder image must be able to
# satisfy the newest module in the graph.
FROM golang:1.26-alpine AS builder
RUN apk add --no-cache git ca-certificates

WORKDIR /app

# Resolve the graph once from go.mod instead of letting `go get -d -v` silently
# upgrade modules to their latest releases on every build.
COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN go mod tidy \
 && CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags="-w -s" -o /app/main .

FROM scratch

COPY --from=builder /app/main .
COPY --from=builder /app/templates/ templates

CMD ["./main"]