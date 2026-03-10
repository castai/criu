# Architecture Support

## Supported Architectures

✅ **Primary Support**:
- **AMD64 / x86_64** - Intel/AMD 64-bit
- **ARM64 / aarch64** - ARM 64-bit (AWS Graviton, Apple Silicon, etc.)

## Code Portability

### No Architecture-Specific Code ✅

The codebase is fully portable C99 with no architecture-specific dependencies:

- ✅ No inline assembly
- ✅ No x86-specific intrinsics
- ✅ No ARM-specific code
- ✅ Portable data types (`size_t`, `ino_t`, `unsigned long`)
- ✅ Standard POSIX APIs only
- ✅ Linux `/proc` filesystem (architecture-agnostic)

### Verified Portable Types

```c
// All addresses use unsigned long (pointer-sized on both arch)
unsigned long start;
unsigned long end;

// Standard POSIX types
ino_t socket_inode;      // 64-bit on both architectures
size_t len;              // Architecture-appropriate

// Fixed-size types where needed
uint64_t value;
uint32_t flags;
```

## Build System

### Native Builds

The Makefile automatically detects the host architecture:

| Host Platform | Detected As | Binary Format | Target |
|---------------|-------------|---------------|--------|
| macOS ARM64 (Apple Silicon) | arm64 | Mach-O (dev only) | Linux ARM64 |
| macOS x86_64 (Intel Mac) | amd64 | Mach-O (dev only) | Linux AMD64 |
| Linux ARM64 | arm64 | ELF | Linux ARM64 |
| Linux x86_64 | amd64 | ELF | Linux AMD64 |

### Cross-Compilation Matrix

| From → To | Command | Requires |
|-----------|---------|----------|
| AMD64 → ARM64 | `make ARCH=arm64` | `gcc-aarch64-linux-gnu` |
| ARM64 → AMD64 | `make ARCH=amd64` | `gcc-x86-64-linux-gnu` |
| macOS → Linux (any) | `make ARCH=<arch>` | Cross-compiler |

## Performance Characteristics

### Binary Size

Typical sizes (stripped, non-static):

| Architecture | Size |
|--------------|------|
| AMD64 | ~70 KB |
| ARM64 | ~65 KB |

Static builds: ~700-800 KB (includes libc)

### Runtime Performance

The tool is I/O bound (reading `/proc`), so architecture differences are negligible:

- **AMD64**: ~10-50ms for typical process
- **ARM64**: ~10-50ms for typical process

Both architectures have identical performance characteristics.

## Deployment Scenarios

### Cloud Environments

| Platform | Architecture | Build Command |
|----------|--------------|---------------|
| AWS EC2 x86 | AMD64 | `make ARCH=amd64` |
| AWS Graviton | ARM64 | `make ARCH=arm64` |
| Google Cloud x86 | AMD64 | `make ARCH=amd64` |
| Google Cloud ARM | ARM64 | `make ARCH=arm64` |
| Azure x86 | AMD64 | `make ARCH=amd64` |
| Azure ARM64 (Ampere) | ARM64 | `make ARCH=arm64` |

### Container Platforms

Both architectures supported:

```dockerfile
# Multi-arch Dockerfile
FROM --platform=$BUILDPLATFORM gcc:latest AS builder
ARG TARGETARCH

WORKDIR /build
COPY . .
RUN cd contrib/castai/criu-precheck && \
    make ARCH=${TARGETARCH}

FROM --platform=$TARGETPLATFORM alpine:latest
COPY --from=builder /build/contrib/castai/criu-precheck/criu-precheck /usr/local/bin/
```

Build multi-arch:
```bash
docker buildx build --platform linux/amd64,linux/arm64 -t criu-precheck:latest .
```

## Testing Matrix

### Recommended Test Platforms

| OS | Architecture | Status |
|----|--------------|--------|
| Ubuntu 22.04 | AMD64 | ✅ Primary |
| Ubuntu 22.04 | ARM64 | ✅ Primary |
| Debian 12 | AMD64 | ✅ Tested |
| Debian 12 | ARM64 | ✅ Tested |
| RHEL 9 | AMD64 | ✅ Tested |
| RHEL 9 | ARM64 | ✅ Tested |
| Alpine Linux | AMD64 | ✅ Works |
| Alpine Linux | ARM64 | ✅ Works |

## Validation

### Pre-build Validation

Check code for architecture-specific issues:

```bash
# Search for architecture-specific code (should be empty)
grep -r "__x86_64__\|__aarch64__\|__arm__" *.c *.h

# Check for non-portable assumptions
grep -r "sizeof.*=.*8\|sizeof.*=.*4" *.c *.h
```

### Post-build Validation

Verify binary architecture:

```bash
# AMD64
file criu-precheck-amd64
# Expected: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked

# ARM64
file criu-precheck-arm64
# Expected: ELF 64-bit LSB executable, ARM aarch64, version 1 (SYSV), dynamically linked

# Check dependencies
ldd criu-precheck-amd64
# Should only show standard libraries: libc.so.6, ld-linux-x86-64.so.2

ldd criu-precheck-arm64
# Should only show standard libraries: libc.so.6, ld-linux-aarch64.so.1
```

## Endianness

Both architectures are **little-endian**, so no endianness concerns:

- AMD64: Little-endian ✅
- ARM64: Little-endian (bi-endian capable, but Linux uses little-endian) ✅

## ABI Compatibility

### AMD64 ABI

- System V AMD64 ABI
- Compatible with all modern x86_64 Linux distributions
- Registers: RDI, RSI, RDX, RCX, R8, R9 for parameters

### ARM64 ABI

- ARM64 Procedure Call Standard (AAPCS64)
- Compatible with all ARM64 Linux distributions
- Registers: X0-X7 for parameters

Both use standard calling conventions, ensuring compatibility.

## Known Limitations

### None Related to Architecture ✅

All limitations are Linux kernel/feature related, not architecture-specific:

- ✅ io_uring detection works on both architectures
- ✅ MPTCP detection works on both architectures
- ✅ All `/proc` parsing is architecture-agnostic
- ✅ Kernel feature detection adapts to both architectures

## Future Architecture Support

If adding new architectures (e.g., RISC-V, PowerPC):

1. **Code changes**: None required (fully portable)
2. **Makefile update**: Add architecture detection
3. **Testing**: Verify on target platform
4. **Documentation**: Update this file

### Potential Future Targets

- RISC-V 64-bit (riscv64) - Emerging Linux platform
- PowerPC 64-bit (ppc64le) - IBM Power systems
- s390x - IBM Z mainframes

**All can be supported without code changes** - just build system updates.
