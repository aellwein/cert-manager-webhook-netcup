FROM --platform=$BUILDPLATFORM golang:1.20.5 AS build
WORKDIR /workspace
COPY go.mod go.sum .
RUN go mod download
COPY . .
ARG TARGETOS TARGETARCH
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -o webhook -ldflags '-w -extldflags "-static"' .

FROM busybox:1.36.1-glibc
COPY --from=build /workspace/webhook /usr/local/bin/webhook
ENTRYPOINT ["webhook"]
