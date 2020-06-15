# Go parameters
export BUILD_VERSION=$(shell cat RELEASE.json | jq -r .Version)
GOCMD=go
GOBUILD=GOPRIVATE="github.com/crowdsecurity" $(GOCMD) build
GOCLEAN=$(GOCMD) clean
GOTEST=$(GOCMD) test
GOGET=$(GOCMD) get


PREFIX?="/"
PID_DIR = $(PREFIX)"/var/run/"
BINARY_NAME=custom-blocker

all: clean test build

static: clean
	$(GOBUILD) -o $(BINARY_NAME) -v -a -tags netgo -ldflags '-w -extldflags "-static"'

build: clean
	$(GOBUILD) -o $(BINARY_NAME) -v

test:
	@$(GOTEST) -v ./...

clean:
	@rm -f $(BINARY_NAME)


RELDIR = "cs-custom-blocker-${BUILD_VERSION}"

.PHONY: release
release: build
	@if [ -d $(RELDIR) ]; then echo "$(RELDIR) already exists, clean" ;  exit 1 ; fi
	@echo Building Release to dir $(RELDIR)
	@mkdir $(RELDIR)/
	@cp $(BINARY_NAME) $(RELDIR)/
	@cp -R ./config $(RELDIR)/
	@cp install.sh $(RELDIR)/
	@cp uninstall.sh $(RELDIR)/
	@chmod +x $(RELDIR)/install.sh
	@chmod +x $(RELDIR)/uninstall.sh
	@tar cvzf cs-custom-blocker.tgz $(RELDIR)
	@rm -rf $(RELDIR)
