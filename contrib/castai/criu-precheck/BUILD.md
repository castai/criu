# Building criu-precheck

## Quick Start

### Native Build
```bash
make
```

This builds a binary for your current architecture.

## Cross-Compilation

### Prerequisites

Install cross-compilation toolchains:

#### On Ubuntu/Debian:
```bash
# For ARM64 targets (from AMD64 host)
sudo apt-get install gcc-aarch64-linux-gnu

# For AMD64 targets (from ARM64 host)
sudo apt-get install gcc-x86-64-linux-gnu

# Or install both
sudo apt-get install gcc-aarch64-linux-gnu gcc-x86-64-linux-gnu
```

#### On Fedora/RHEL:
```bash
# For ARM64 targets
sudo dnf install gcc-aarch64-linux-gnu

# For AMD64 targets
sudo dnf install gcc-x86-64-linux-gnu
```

### Build Targets

#### Build for AMD64 (x86_64):
```bash
make clean
make ARCH=amd64
file criu-precheck
# Output: criu-precheck: ELF 64-bit LSB executable, x86-64, ...
```

#### Build for ARM64 (aarch64):
```bash
make clean
make ARCH=arm64
file criu-precheck
# Output: criu-precheck: ELF 64-bit LSB executable, ARM aarch64, ...
```

#### Build Both Architectures:
```bash
make all-arch
```

This creates:
- `criu-precheck-amd64` - AMD64/x86_64 binary
- `criu-precheck-arm64` - ARM64/aarch64 binary

### Custom Cross-Compiler

If your cross-compiler has a different prefix:

```bash
make CROSS_COMPILE=aarch64-unknown-linux-gnu-
```

## Static Linking

For deployment without dependencies:

```bash
make STATIC=1
# Creates: criu-precheck-static
```

Static binaries are larger but can run on any Linux system with the same architecture.

## Build Options Summary

| Command | Description |
|---------|-------------|
| `make` | Native build for current architecture |
| `make ARCH=amd64` | Build for AMD64/x86_64 |
| `make ARCH=arm64` | Build for ARM64/aarch64 |
| `make STATIC=1` | Static linked binary |
| `make all-arch` | Build all architectures |
| `make clean` | Clean build artifacts |
| `make test-amd64` | Build and verify AMD64 |
| `make test-arm64` | Build and verify ARM64 |

## Architecture Detection

The Makefile automatically detects your host architecture:

- **macOS ARM64** → Builds for Linux ARM64 (native)
- **macOS x86_64** → Builds for Linux AMD64 (native)
- **Linux ARM64** → Builds for Linux ARM64 (native)
- **Linux x86_64** → Builds for Linux AMD64 (native)

Cross-compilation is only attempted when `ARCH=` differs from host.

## Verification

After building, verify the binary:

```bash
# Check architecture
file criu-precheck

# Check it runs (even on macOS, --help works)
./criu-precheck --help

# On Linux, check dependencies
ldd criu-precheck
# Output should show standard libraries only
```

## Docker Cross-Compilation (Alternative)

If you don't have cross-compilers installed, use Docker:

### AMD64 Build:
```bash
docker run --rm -v $(pwd):/work -w /work \
  gcc:latest \
  make clean all ARCH=amd64
```

### ARM64 Build:
```bash
docker run --rm -v $(pwd):/work -w /work \
  --platform linux/arm64 \
  gcc:latest \
  make clean all ARCH=arm64
```

## CI/CD Integration

### GitHub Actions Example:

```yaml
name: Build Multi-Arch

on: [push]

jobs:
  build:
    strategy:
      matrix:
        arch: [amd64, arm64]
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2

      - name: Install cross-compiler
        if: matrix.arch == 'arm64'
        run: sudo apt-get install -y gcc-aarch64-linux-gnu

      - name: Build
        run: |
          cd contrib/castai/criu-precheck
          make ARCH=${{ matrix.arch }}
          mv criu-precheck criu-precheck-${{ matrix.arch }}

      - name: Upload
        uses: actions/upload-artifact@v2
        with:
          name: criu-precheck-${{ matrix.arch }}
          path: contrib/castai/criu-precheck/criu-precheck-${{ matrix.arch }}
```

## Troubleshooting

### "gcc: command not found"
Install gcc: `sudo apt-get install build-essential`

### "aarch64-linux-gnu-gcc: command not found"
Install ARM64 cross-compiler: `sudo apt-get install gcc-aarch64-linux-gnu`

### "x86_64-linux-gnu-gcc: command not found"
Install AMD64 cross-compiler: `sudo apt-get install gcc-x86-64-linux-gnu`

### Binary won't run on target
1. Check architecture: `file criu-precheck`
2. Check dependencies: `ldd criu-precheck`
3. Try static build: `make STATIC=1`

### Compilation errors about missing headers
Ensure you have libc development files:
```bash
sudo apt-get install libc6-dev
# For cross-compilation:
sudo apt-get install libc6-dev-arm64-cross  # ARM64
sudo apt-get install libc6-dev-amd64-cross  # AMD64
```

## Testing on Target

After building, test on the target Linux system:

```bash
# Copy to target
scp criu-precheck user@linux-host:/tmp/

# On Linux host
ssh user@linux-host
cd /tmp
chmod +x criu-precheck

# Test with a simple process
sleep 1000 &
PID=$!
sudo ./criu-precheck -t $PID

# Clean up
kill $PID
```

## Size Optimization

### Smaller Binary:
```bash
# Strip symbols
make
strip criu-precheck
# Reduces size by ~30%

# Or build with optimization
make CFLAGS="-Os -flto"
```

### Static + Stripped:
```bash
make STATIC=1
strip criu-precheck-static
# Fully standalone, optimized size
```

## Development Builds

### Debug Build:
```bash
make CFLAGS="-g -O0 -DDEBUG"
```

### With Address Sanitizer:
```bash
make CFLAGS="-g -fsanitize=address"
```

## Platform-Specific Notes

### macOS
- Builds Linux binaries (uses ELF format, not Mach-O)
- Binary won't run on macOS (Linux `/proc` filesystem required)
- Use for cross-compilation only
- Testing requires Linux VM or container

### Windows (WSL)
- WSL2 with Ubuntu recommended
- Install build-essential: `sudo apt-get install build-essential`
- Cross-compilers available via apt
- Can test binaries directly in WSL2

### Alpine Linux
- Use `musl-dev` instead of `libc6-dev`
- Cross-compilation limited (musl-cross recommended)
- Static builds recommended for portability
