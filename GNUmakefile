default: testacc

testacc:
	TF_ACC=1 go test ./... -v $(TESTARGS) -timeout 120m
format:
	go fmt ./...
	terraform fmt -recursive
generate:
	go generate ./...

# Run acceptance tests
.PHONY: testacc generate format