BINARY  := go_clickjack
DESTDIR := $(HOME)/.local/bin

.PHONY: build dev check install clean

dev:
	npm run dev

build:
	npm run build
	go build -o $(BINARY) .

check:
	npm run check
	go vet ./...

install: build
	install -m 755 $(BINARY) $(DESTDIR)/$(BINARY)

clean:
	rm -f $(BINARY) static/app.js
