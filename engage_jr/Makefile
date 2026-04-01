BINARY  := engage_jr
DESTDIR := /usr/local/bin

.PHONY: build test install clean

build:
	go build -o $(BINARY) .

test:
	go vet ./...
	go test ./...

install: build
	install -m 755 $(BINARY) $(DESTDIR)/$(BINARY)

clean:
	rm -f $(BINARY)
