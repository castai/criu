# CRIU Pre-Check Tool

**Non-invasive CRIU checkpoint/restore compatibility analyzer**

## What It Does

Analyzes a running Linux process to predict CRIU checkpoint/restore compatibility **without** causing downtime (no process freeze, no ptrace, no parasite injection).

## Critical Features Detected

### ✅ Implemented Checks:

1. **io_uring Detection** (CRITICAL)
   - Scans FDs and VMAs for `io_uring` usage
   - **Result**: Guaranteed dump failure if detected

2. **MPTCP Detection** (CRITICAL) ⭐ NEW!
   - Checks `/proc/<PID>/net/mptcp` for Multipath TCP usage
   - **Result**: Guaranteed dump failure - MPTCP NOT supported by CRIU
   - **Remediation**:
     - Go programs: `GODEBUG=multipathtcp=0`
     - System-wide: `echo 0 > /proc/sys/net/mptcp/enabled`

3. **RSEQ + Kernel Support** (CRITICAL)
   - Detects modern glibc (2.35+) usage
   - Validates kernel has `PTRACE_GET_RSEQ_CONFIGURATION`
   - **Result**: Dump fails if RSEQ detected without kernel support

4. **SysVIPC without IPC Namespace** (CRITICAL)
   - Checks for SysVIPC VMAs without IPC namespace isolation
   - **Result**: Guaranteed dump failure

5. **Process State Issues** (CRITICAL)
   - Zombie processes (state Z)
   - Stopped processes (state T)
   - Invalid session ID (sid == 0)
   - **Result**: Dump failure

6. **TCP ESTABLISHED Connections** (WARNING)
   - Parses `/proc/<PID>/net/tcp{,6}`
   - Suggests `--tcp-established` flag

7. **AIO Ring Misalignment** (CRITICAL)
   - Validates AIO ring sizes are page-aligned

8. **Multithreading** (INFO)
   - Reports thread count
   - Ensures kernel supports multi-threaded ptrace

9. **Namespace Isolation**
   - Detects PID, NET, MNT, IPC, UTS, USER, CGROUP, TIME namespaces

10. **Kernel Feature Validation**
    - Checks kernel version for required features
    - Validates `tcp_repair`, `userns`, `memfd`, `uffd`, etc.

## Usage

```bash
# Basic check
sudo criu-precheck -t <PID>

# JSON output
sudo criu-precheck -t <PID> --json

# Verbose mode
sudo criu-precheck -t <PID> -v

# Integration mode (exit codes only)
sudo criu-precheck -t <PID> --exit-code-only
```

## Exit Codes (with `--exit-code-only`)

- `0` - Very likely to succeed (90%+)
- `1` - Likely to succeed (70-89%)
- `2` - Uncertain (40-69%)
- `3` - Unlikely to succeed (<40%)
- `4` - Guaranteed to fail (critical issue detected)

## Example Output

```
CRIU Pre-Check Report for PID 12345
====================================

PROCESS INFO:
  Command:     my-app
  State:       S (Sleeping)
  Threads:     4
  Session:     12340 (valid)

COMPATIBILITY: 0% unlikely
  ✅ PASSED: 2 checks
  ⚠️  WARNINGS: 1 checks
  ❌ FAILED: 2 checks

CRITICAL ISSUES:
  ❌ MPTCP (Multipath TCP) detected - 3 connection(s)
     → RECOMMENDATION: MPTCP is NOT supported by CRIU. Disable MPTCP before checkpoint.
        For Go programs: set GODEBUG=multipathtcp=0 environment variable.
        For system-wide: echo 0 > /proc/sys/net/mptcp/enabled
     → AFFECTED: network

  ❌ io_uring detected - CRIU checkpoint will likely fail
     → RECOMMENDATION: Close io_uring before checkpoint, or skip this process.
     → AFFECTED: fd:5

WARNINGS:
  ⚠️  1 active TCP ESTABLISHED connection(s) detected
     → RECOMMENDATION: Use --tcp-established flag with CRIU dump.

RESOURCE SUMMARY:
  Memory:
    - VMAs: 156
    - Private pages: ~245 MB
    - Shared pages: ~89 MB

  File Descriptors: 24
    - Regular files: 8
    - Sockets: 12 (1 TCP ESTABLISHED)
    - Special: 4 (includes io_uring)

  Namespaces:
    - PID namespace: isolated (ino:4026532123)
    - Network namespace: isolated (ino:4026532124)
    - Mount namespace: default (ino:4026531840)
    - IPC namespace: default (ino:4026531839)

KERNEL FEATURES:
  ✅ tcp_repair
  ✅ ptrace_get_rseq_conf
  ✅ userns
  ✅ memfd
```

## Architecture

```
main.c              - CLI entry point
common.c/.h         - Utilities, issue tracking
proc_reader.c/.h    - /proc parsing (non-invasive)
feature_detector.c/.h - Critical feature detection
  ├─ detect_io_uring()
  ├─ detect_mptcp()              ⭐ NEW!
  ├─ detect_rseq_usage()
  ├─ detect_network_features()
  ├─ detect_sysvipc_issues()
  ├─ check_aio_ring_alignment()
  └─ detect_multithreading()
resource_checker.c/.h - Resource validation
namespace_analyzer.c/.h - Namespace checks
compatibility.c/.h    - Scoring algorithm
report.c/.h          - Output formatting
```

## Building

### Quick Start (Native)
```bash
cd contrib/castai/criu-precheck
make
```

### Cross-Compilation

**Build for AMD64 (x86_64):**
```bash
make ARCH=amd64
```

**Build for ARM64 (aarch64):**
```bash
make ARCH=arm64
```

**Build both architectures:**
```bash
make all-arch
# Creates: criu-precheck-amd64, criu-precheck-arm64
```

**Static build (no dependencies):**
```bash
make STATIC=1
```

### Requirements

- **Native build**: gcc, make
- **Cross-compilation**:
  ```bash
  # Ubuntu/Debian
  sudo apt-get install gcc-aarch64-linux-gnu gcc-x86-64-linux-gnu

  # Fedora/RHEL
  sudo dnf install gcc-aarch64-linux-gnu gcc-x86-64-linux-gnu
  ```

See [BUILD.md](BUILD.md) for detailed cross-compilation guide.

## Architecture Support

✅ **Fully Supported**:
- AMD64 / x86_64
- ARM64 / aarch64

✅ **Tested Platforms**:
- Ubuntu 20.04+ (AMD64, ARM64)
- Debian 11+ (AMD64, ARM64)
- RHEL/CentOS 8+ (AMD64, ARM64)
- Alpine Linux (AMD64, ARM64)

**Note**: This tool is **Linux-only** (requires `/proc` filesystem).

## Testing on Linux

This tool requires a Linux system with `/proc` filesystem. It will NOT work on macOS.

Test scenarios:
1. Simple process: `sleep 1000 &` - should score 90%+
2. io_uring app: Rust tokio application - should detect io_uring
3. Go app with MPTCP: Go 1.21+ server - should detect MPTCP
4. TCP server: nginx - should warn about TCP connections
5. Container: Docker process - should detect namespaces

## Future Enhancements

- [ ] Mount point external filesystem detection
- [ ] POSIX timer validation
- [ ] Cgroup v2 detailed checks
- [ ] LSM (AppArmor/SELinux) profile analysis
- [ ] Suggested CRIU command generation
- [ ] Web UI dashboard

## References

- CRIU MPTCP handling: `criu/sk-inet.c:138-140`
- CRIU design doc: `/contrib/castai/PRECHECK_DESIGN.md`
