NAME=miaospeed
BINDIR=bin
MIHOMO_VERSION=$(shell grep -m1 "github.com/metacubex/mihomo" go.mod | awk '{print $2}' || echo "Unknown")
VERSION=$(shell git describe --tags --abbrev=0 | head -n 1 || echo "Unknown")
BUILDTIME=$(shell date -u '+%Y-%m-%d_%I:%M:%S%p(UTC%:z)')
COMMIT=$(shell git rev-parse --short HEAD || echo "Unknown")
GOBUILD=CGO_ENABLED=0 go build -trimpath -ldflags '-X "main.VERSION=$(VERSION)" \
		-X "main.COMPILATIONTIME=$(BUILDTIME)" \
		-X "main.COMMIT=$(COMMIT)" \
		-X "main.MihomoVersion=$(MIHOMO_VERSION)" \
		-w -s -buildid='

PLATFORM_LIST = \
	darwin-amd64 \
	darwin-amd64-v3 \
	darwin-arm64 \
	linux-386 \
	linux-amd64 \
	linux-amd64-v3 \
	linux-armv5 \
	linux-armv6 \
	linux-armv7 \
	linux-arm64 \
	linux-mips-softfloat \
	linux-mips-hardfloat \
	linux-mipsle-softfloat \
	linux-mipsle-hardfloat \
	linux-mips64 \
	linux-mips64le \
	linux-riscv64 \
	linux-loong64 \
	freebsd-386 \
	freebsd-amd64 \
	freebsd-amd64-v3 \
	freebsd-arm64

WINDOWS_ARCH_LIST = \
	windows-386 \
	windows-amd64 \
	windows-amd64-v3 \
	windows-arm64

all: linux-amd64 linux-386 darwin-amd64 darwin-arm64 windows-amd64 windows-386 windows-arm64 linux-arm64 linux-armv7 linux-riscv64 linux-loong64 freebsd-amd64 freebsd-arm64# Most used

darwin-amd64:
	GOARCH=amd64 GOOS=darwin $(GOBUILD) -o $(BINDIR)/$(NAME)-$@

darwin-amd64-v3:
	GOARCH=amd64 GOOS=darwin GOAMD64=v3 $(GOBUILD) -o $(BINDIR)/$(NAME)-$@

darwin-arm64:
	GOARCH=arm64 GOOS=darwin $(GOBUILD) -o $(BINDIR)/$(NAME)-$@

linux-386:
	GOARCH=386 GOOS=linux $(GOBUILD) -o $(BINDIR)/$(NAME)-$@

linux-amd64:
	GOARCH=amd64 GOOS=linux $(GOBUILD) -o $(BINDIR)/$(NAME)-$@

linux-amd64-v3:
	GOARCH=amd64 GOOS=linux GOAMD64=v3 $(GOBUILD) -o $(BINDIR)/$(NAME)-$@

linux-armv5:
	GOARCH=arm GOOS=linux GOARM=5 $(GOBUILD) -o $(BINDIR)/$(NAME)-$@

linux-armv6:
	GOARCH=arm GOOS=linux GOARM=6 $(GOBUILD) -o $(BINDIR)/$(NAME)-$@

linux-armv7:
	GOARCH=arm GOOS=linux GOARM=7 $(GOBUILD) -o $(BINDIR)/$(NAME)-$@

linux-arm64:
	GOARCH=arm64 GOOS=linux $(GOBUILD) -o $(BINDIR)/$(NAME)-$@

linux-mips-softfloat:
	GOARCH=mips GOMIPS=softfloat GOOS=linux $(GOBUILD) -o $(BINDIR)/$(NAME)-$@

linux-mips-hardfloat:
	GOARCH=mips GOMIPS=hardfloat GOOS=linux $(GOBUILD) -o $(BINDIR)/$(NAME)-$@

linux-mipsle-softfloat:
	GOARCH=mipsle GOMIPS=softfloat GOOS=linux $(GOBUILD) -o $(BINDIR)/$(NAME)-$@

linux-mipsle-hardfloat:
	GOARCH=mipsle GOMIPS=hardfloat GOOS=linux $(GOBUILD) -o $(BINDIR)/$(NAME)-$@

linux-mips64:
	GOARCH=mips64 GOOS=linux $(GOBUILD) -o $(BINDIR)/$(NAME)-$@

linux-mips64le:
	GOARCH=mips64le GOOS=linux $(GOBUILD) -o $(BINDIR)/$(NAME)-$@

linux-riscv64:
	GOARCH=riscv64 GOOS=linux $(GOBUILD) -o $(BINDIR)/$(NAME)-$@

linux-loong64:
	GOARCH=loong64 GOOS=linux $(GOBUILD) -o $(BINDIR)/$(NAME)-$@

freebsd-386:
	GOARCH=386 GOOS=freebsd $(GOBUILD) -o $(BINDIR)/$(NAME)-$@

freebsd-amd64:
	GOARCH=amd64 GOOS=freebsd $(GOBUILD) -o $(BINDIR)/$(NAME)-$@

freebsd-amd64-v3:
	GOARCH=amd64 GOOS=freebsd GOAMD64=v3 $(GOBUILD) -o $(BINDIR)/$(NAME)-$@

freebsd-arm64:
	GOARCH=arm64 GOOS=freebsd $(GOBUILD) -o $(BINDIR)/$(NAME)-$@

windows-386:
	GOARCH=386 GOOS=windows $(GOBUILD) -o $(BINDIR)/$(NAME)-$@.exe

windows-amd64:
	GOARCH=amd64 GOOS=windows $(GOBUILD) -o $(BINDIR)/$(NAME)-$@.exe

windows-amd64-v3:
	GOARCH=amd64 GOOS=windows GOAMD64=v3 $(GOBUILD) -o $(BINDIR)/$(NAME)-$@.exe

windows-arm64:
	GOARCH=arm64 GOOS=windows $(GOBUILD) -o $(BINDIR)/$(NAME)-$@.exe

android-so:
	GOOS=android GOARCH=arm64 $(GOBUILD) -o android/app/src/main/jniLibs/arm64-v8a/libmiaospeed.so .

android-apk: android-so
	cd android && ./gradlew assembleRelease
	mkdir -p $(BINDIR)
	cp android/app/build/outputs/apk/release/miaospeed-$(shell git describe --tags --abbrev=0)-arm64-v8a.apk $(BINDIR)/

android: android-apk

gz_releases=$(addsuffix .gz, $(PLATFORM_LIST))
zip_releases=$(addsuffix .zip, $(WINDOWS_ARCH_LIST))

#$(gz_releases): %.gz : %
#	chmod +x $(BINDIR)/$(NAME)-$(basename $@)
#	gzip -f -S -$(VERSION).gz $(BINDIR)/$(NAME)-$(basename $@)
#
#$(zip_releases): %.zip : %
#	zip -m -j $(BINDIR)/$(NAME)-$(basename $@)-$(VERSION).zip $(BINDIR)/$(NAME)-$(basename $@).exe
$(gz_releases): %.gz : %
	chmod +x $(BINDIR)/$(NAME)-$(basename $@)
	tar -czf $(BINDIR)/$(NAME)-$(basename $@)-$(VERSION).tar.gz -C $(BINDIR) $(NAME)-$(basename $@) -C .. LICENSE
	rm $(BINDIR)/$(NAME)-$(basename $@)

$(zip_releases): %.zip : %
	zip -j $(BINDIR)/$(NAME)-$(basename $@)-$(VERSION).zip $(BINDIR)/$(NAME)-$(basename $@).exe LICENSE
	rm $(BINDIR)/$(NAME)-$(basename $@).exe

all-arch: $(PLATFORM_LIST) $(WINDOWS_ARCH_LIST)

releases: $(gz_releases) $(zip_releases)

LINT_OS_LIST := darwin windows linux freebsd openbsd

lint: $(foreach os,$(LINT_OS_LIST),$(os)-lint)
%-lint:
	GOOS=$* golangci-lint run ./...

lint-fix: $(foreach os,$(LINT_OS_LIST),$(os)-lint-fix)
%-lint-fix:
	GOOS=$* golangci-lint run --fix ./...

clean:
	rm $(BINDIR)/*
