build:
	@mkdir -p bin
	go build -o ./bin/in-toto-policies

run-test:
	go run ./... verify ./test/data/policy.yaml \
		--functionary-directory ./test/data/ \
		--attestation-directory ./test/data/

clean:
	rm -rf bin
