vet:
	go vet ./...

test:
	go test ./...

# for the local builds
build:
	go build ./...

clean:
	$(RM) cert-manager-webhook-netcup
