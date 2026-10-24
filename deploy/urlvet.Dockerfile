FROM golang:1.25-alpine AS builder
RUN apk add --no-cache git
WORKDIR /source
RUN git init && git remote add origin https://github.com/urlvet/urlvet.git && git fetch --depth=1 origin 657a8dafeb9c9109a339087ea07cf922aaddc52a && git checkout --detach FETCH_HEAD && test "$(git rev-parse HEAD)" = 657a8dafeb9c9109a339087ea07cf922aaddc52a
# Upstream allows 20 requests a minute per client address. Every MyScanner scan reaches this
# private, unpublished instance from the same worker address, so that cap is site-wide and
# turned half of a 20-scan burst into partial reports (HTTP 429). The build fails if upstream moves it.
RUN sed -i 's/middleware.RateLimiter(20, time.Minute)/middleware.RateLimiter(300, time.Minute)/' server/internal/handler/router.go && grep -q 'middleware.RateLimiter(300, time.Minute)' server/internal/handler/router.go
WORKDIR /source/server
RUN go mod download && CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /urlvet ./cmd/urlvet
FROM alpine:3.22
RUN apk add --no-cache ca-certificates tzdata && addgroup -g 10001 urlvet && adduser -D -u 10001 -G urlvet urlvet
WORKDIR /app
COPY --from=builder /urlvet /app/urlvet
COPY --from=builder /source/server/assets /app/assets
COPY urlvet-entrypoint.sh /app/entrypoint.sh
RUN sed -i 's/\r$//' /app/entrypoint.sh && chmod 755 /app/entrypoint.sh && mkdir -p /app/data /app/tmp && chown -R 10001:10001 /app
USER 10001:10001
ENTRYPOINT ["/app/entrypoint.sh"]
