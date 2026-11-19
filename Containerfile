FROM golang:1.27-alpine@sha256:70bd7ddea8b6cbe5d6943cde279d6b67feb10cc924fb9100d1d8757c1575b280 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/dns-ip-list-chunker .
RUN mkdir -p /out/data

FROM scratch
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=build /out/dns-ip-list-chunker /dns-ip-list-chunker
# Default exclusions volume mount point, owned by the runtime user so a
# fresh named volume inherits write access.
COPY --from=build --chown=65534:65534 /out/data /data
VOLUME ["/data"]
USER 65534:65534
EXPOSE 8080
ENTRYPOINT ["/dns-ip-list-chunker"]
