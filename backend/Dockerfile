FROM golang:1.26-alpine AS build

WORKDIR /src
# Dependencies first: this layer is cached until go.mod/go.sum actually change.
COPY go.mod go.sum ./
RUN go mod download
COPY backend ./backend

# CGO off is what makes the binary static -- the final image has no libc to link
# against. It also picks Go's own DNS resolver over getaddrinfo, which is the
# one the SSRF guard is written against.
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" \
      -o /out/scanner ./backend/cmd/server

FROM scratch

# The process opens TLS connections to attacker-chosen public hosts, so it needs
# the root CA bundle...
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=build /out/scanner /scanner

# ...and nothing else. No shell, no package manager, no writable filesystem, and
# an unprivileged numeric UID that exists in no passwd file.
USER 10001:10001

EXPOSE 8000

# There is no curl in here to call, so the binary checks itself.
HEALTHCHECK --interval=30s --timeout=3s --start-period=2s \
  CMD ["/scanner", "-health"]

ENTRYPOINT ["/scanner"]
