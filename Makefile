# for the local builds
build:
	go build ./...

vet:
	go vet ./...

test:
	go test ./...

clean:
	$(RM) cert-manager-webhook-netcup
