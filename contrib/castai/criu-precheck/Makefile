# Cross-compilation support
# Usage:
#   make                          # Native build
#   make ARCH=amd64               # AMD64/x86_64 Linux build (requires cross-compiler on non-x86_64)
#   make ARCH=arm64               # ARM64/aarch64 Linux build (requires cross-compiler on non-aarch64)
#   make CROSS_COMPILE=aarch64-linux-gnu-  # Custom cross-compiler

# Detect host OS and architecture
HOST_OS := $(shell uname -s)
HOST_ARCH := $(shell uname -m)

# Default to native build
ARCH ?= native

# Normalize architecture names
ifeq ($(HOST_ARCH),x86_64)
    NATIVE_ARCH := amd64
endif
ifeq ($(HOST_ARCH),aarch64)
    NATIVE_ARCH := arm64
endif
ifeq ($(HOST_ARCH),arm64)
    NATIVE_ARCH := arm64
endif

# If ARCH=native, use host architecture
ifeq ($(ARCH),native)
    ARCH := $(NATIVE_ARCH)
endif

# Normalize requested architecture
ifeq ($(ARCH),x86_64)
    ARCH := amd64
endif
ifeq ($(ARCH),aarch64)
    ARCH := arm64
endif

# Determine if cross-compilation is needed
NEED_CROSS := no
ifneq ($(ARCH),$(NATIVE_ARCH))
    NEED_CROSS := yes
endif

# Set cross-compiler only if actually cross-compiling Linux binaries
ifeq ($(NEED_CROSS),yes)
    ifeq ($(ARCH),amd64)
        CROSS_COMPILE ?= x86_64-linux-gnu-
        CFLAGS_ARCH := -m64
    endif
    ifeq ($(ARCH),arm64)
        CROSS_COMPILE ?= aarch64-linux-gnu-
        CFLAGS_ARCH :=
    endif
else
    # Native build
    CROSS_COMPILE ?=
    CFLAGS_ARCH :=
endif

CC := $(CROSS_COMPILE)gcc
CFLAGS := -Wall -Wextra -O2 -std=gnu99 -I. $(CFLAGS_ARCH)
LDFLAGS :=

TARGET := criu-precheck

SRCS := main.c \
	common.c \
	proc_reader.c \
	feature_detector.c \
	resource_checker.c \
	namespace_analyzer.c \
	network_inspector.c \
	mount_analyzer.c \
	compatibility.c \
	report.c

OBJS := $(SRCS:.c=.o)
DEPS := $(SRCS:.c=.d)

# Static build option for easier deployment
ifdef STATIC
    LDFLAGS += -static
    TARGET := $(TARGET)-static
endif

# Version info
VERSION := 1.0.0
BUILD_DATE := $(shell date +%Y-%m-%d)
BUILD_ARCH := $(ARCH)

.PHONY: all clean install arch-info

all: arch-info $(TARGET)

arch-info:
	@echo "Building criu-precheck v$(VERSION)"
	@echo "  Host: $(HOST_OS)/$(HOST_ARCH)"
	@echo "  Target: Linux/$(BUILD_ARCH)"
	@echo "  Compiler: $(CC)"
	@echo "  Cross-compile: $(NEED_CROSS)"
	@echo "  Date: $(BUILD_DATE)"
	@echo ""

$(TARGET): $(OBJS)
	$(CC) $(LDFLAGS) -o $@ $^

%.o: %.c
	$(CC) $(CFLAGS) -MMD -MP -c -o $@ $<

-include $(DEPS)

clean:
	rm -f $(TARGET) criu-precheck criu-precheck-static $(OBJS) $(DEPS)

install: $(TARGET)
	install -D -m 0755 $(TARGET) $(DESTDIR)/usr/local/bin/criu-precheck

# Cross-compilation test targets
.PHONY: test-amd64 test-arm64
test-amd64:
	@echo "Building for AMD64..."
	$(MAKE) clean
	$(MAKE) ARCH=amd64
	file $(TARGET)

test-arm64:
	@echo "Building for ARM64..."
	$(MAKE) clean
	$(MAKE) ARCH=arm64
	file $(TARGET)

# Build both architectures
.PHONY: all-arch
all-arch:
	@echo "Building all architectures..."
	$(MAKE) clean
	$(MAKE) ARCH=amd64 TARGET=criu-precheck-amd64
	$(MAKE) clean
	$(MAKE) ARCH=arm64 TARGET=criu-precheck-arm64
	@echo "Built binaries:"
	@ls -lh criu-precheck-*
	@file criu-precheck-*

.PHONY: test
test: $(TARGET)
	@echo "Run on Linux: sudo ./$(TARGET) -t \$\$\$$"

# Linting targets
.PHONY: lint lint-clang-tidy lint-cppcheck check-style

lint: check-style lint-cppcheck
	@echo "✅ Lint checks complete"

# Check code style (basic checks without external tools)
check-style:
	@echo "Checking code style..."
	@! grep -rn "^ \+	" *.c *.h 2>/dev/null || (echo "❌ Spaces before tabs found" && false)
	@! grep -rn " $$" *.c *.h 2>/dev/null | grep -v "//" || (echo "⚠️  Trailing whitespace found" && true)
	@! grep -rn "TODO\|FIXME\|XXX\|BUG" *.c *.h 2>/dev/null | grep -v "TODO:" || (echo "⚠️  TODO/FIXME/BUG markers found" && true)
	@echo "✅ Code style checks passed"

# Lint with cppcheck (if available)
lint-cppcheck:
	@if command -v cppcheck >/dev/null 2>&1; then \
		echo "Running cppcheck..."; \
		cppcheck --enable=warning,style,performance,portability \
			--suppress=missingIncludeSystem \
			--suppress=unusedFunction \
			--inline-suppr \
			--quiet \
			*.c 2>&1 | grep -v "Checking.*done" || true; \
		echo "✅ cppcheck complete"; \
	else \
		echo "⚠️  cppcheck not installed (optional)"; \
	fi

# Lint with clang-tidy (if available)
lint-clang-tidy:
	@if command -v clang-tidy >/dev/null 2>&1; then \
		echo "Running clang-tidy..."; \
		clang-tidy *.c -- $(CFLAGS) 2>/dev/null || true; \
		echo "✅ clang-tidy complete"; \
	else \
		echo "⚠️  clang-tidy not installed (optional)"; \
	fi
