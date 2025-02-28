FROM --platform=$BUILDPLATFORM golang:1.24.0 AS build
WORKDIR /workspace
COPY go.mod go.sum .
RUN go mod download
COPY . .
ARG TARGETOS TARGETARCH
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -o webhook -ldflags '-w -extldflags "-static"' .

FROM gcr.io/distroless/static-debian12
LABEL org.opencontainers.image.source=https://github.com/aellwein/cert-manager-webhook-netcup
LABEL org.opencontainers.image.licenses=Apache-2.0
COPY --from=build /workspace/webhook /usr/local/bin/webhook
ENTRYPOINT ["webhook"]
