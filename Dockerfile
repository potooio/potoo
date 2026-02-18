FROM golang:1.25-alpine AS builder

ARG BINARY=controller
ARG TARGETARCH=amd64

WORKDIR /workspace

# Cache dependencies
COPY go.mod go.sum ./
RUN go mod download

# Build
COPY . .
RUN CGO_ENABLED=0 GOOS=linux GOARCH=${TARGETARCH} go build \
    -ldflags="-s -w" \
    -o app ./cmd/${BINARY}/

# ---

FROM gcr.io/distroless/static:nonroot

WORKDIR /
COPY --from=builder /workspace/app .
USER 65532:65532

ENTRYPOINT ["/app"]
