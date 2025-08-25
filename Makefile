default: deps test build

deps:
	@go get -t ./...

test:
	@go test ./...

build: bin/wirepunch

bin:
	@mkdir ${@}
bin/wirepunch: bin
	@go generate .
	@go build -o $(@) .

run: bin/wirepunch
	@./bin/wirepunch

.PHONY: bin/wirepunch
.EXPORT_ALL_VARIABLES: