# PHONY used to mitigate conflict with dir name test
.PHONY: test
test:
	go mod tidy
	go fmt ./...
	go vet ./...
	golint ./...
	go test ./... -v

generatecerts:
	go run cmd/generatecert/main.go	-certpath=test/data/ca -serial=100 -isca -bits=4096
	go run cmd/generatecert/main.go	-certpath=test/data/signed1 -serial=101 -parentpath=test/data/ca
	go run cmd/generatecert/main.go	-certpath=test/data/signed2 -serial=102 -parentpath=test/data/ca
	go run cmd/generatecert/main.go	-certpath=test/data/signed3 -serial=103 -parentpath=test/data/ca
	go run cmd/generatecert/main.go	-certpath=test/data/selfSigned -serial=99

CRT?=test/data/signed1.crt
CACRT?=test/data/ca.crt
printcert:
	openssl x509 -in $(CRT) -text -noout

verifycert:
	openssl verify -CAfile $(CACRT) $(CRT)
