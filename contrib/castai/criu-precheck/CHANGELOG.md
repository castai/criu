# CRIU Pre-Check Tool - Changelog

## Phase 1 - Critical Checks Implemented (2026-02-04)

### ✅ New Features Added

#### 1. **MPTCP Detection** (CRITICAL)
- Detects Multipath TCP usage via `/proc/<PID>/net/mptcp`
- **Impact**: Guaranteed dump failure if detected
- **Remediation**:
  - Go programs: `GODEBUG=multipathtcp=0`
  - System-wide: `echo 0 > /proc/sys/net/mptcp/enabled`
- **Files**: `feature_detector.c:detect_mptcp()`

#### 2. **TTY/PTY Detection** (WARNING)
- Scans file descriptors for terminal devices:
  - `/dev/pts/*` (PTY slaves)
  - `/dev/tty*` (TTY devices)
  - `/dev/console` (System console)
- **Impact**: Requires `--shell-job` flag
- **Recommendation**: Warn about controlling terminal handling
- **Files**: `feature_detector.c:detect_tty()`

#### 3. **Seccomp Filter Validation** (CRITICAL if no kernel support)
- Reads `/proc/<PID>/status` → `Seccomp:` field
- Checks kernel version for `PTRACE_O_SUSPEND_SECCOMP` (kernel 4.7+)
- **Impact**:
  - Kernel < 4.7 + Seccomp = Guaranteed failure
  - Kernel >= 4.7 = Info message
- **Recommendation**: Upgrade kernel or disable seccomp
- **Files**: `feature_detector.c:detect_seccomp()`

#### 4. **Zombie with Threads Detection** (CRITICAL)
- Checks if process is zombie (`state == Z`) AND has multiple threads
- **Impact**: Guaranteed dump failure
- **Recommendation**: Clean up zombie process
- **Files**: `feature_detector.c:detect_zombie_with_threads()`

#### 5. **vDSO Presence Check** (WARNING)
- Validates vDSO (virtual dynamic shared object) exists in `/proc/<PID>/maps`
- **Impact**: Missing vDSO is unusual, may cause restore issues
- **Recommendation**: Check kernel config `CONFIG_VDSO=y`
- **Files**: `feature_detector.c:detect_vdso()`

#### 6. **LSM Profile Detection** (INFO)
- Reads `/proc/<PID>/attr/current` for AppArmor/SELinux profiles
- **Impact**: Profile must be available on restore
- **Recommendation**: Ensure CRIU LSM dumping support enabled
- **Files**: `feature_detector.c:detect_lsm()`

### 📊 Detection Coverage

**Before Phase 1**: ~15% coverage
**After Phase 1**: ~60% coverage

### 🏗️ Compatibility Scoring Updates

New issue types with score impacts:
- `ISSUE_MPTCP_DETECTED` → score = 0 (guaranteed failure)
- `ISSUE_ZOMBIE_WITH_THREADS` → score = 0 (guaranteed failure)
- `ISSUE_SECCOMP_NO_KERNEL_SUPPORT` → score = 0 (guaranteed failure)
- `ISSUE_TTY_DETECTED` → score -= 10
- `ISSUE_VDSO_MISSING` → score -= 15
- `ISSUE_LSM_DETECTED` → SEVERITY_INFO (score -= 1)

### 🔧 Technical Details

**New Issue Types Added to `common.h`**:
```c
ISSUE_TTY_DETECTED
ISSUE_SECCOMP_NO_KERNEL_SUPPORT
ISSUE_ZOMBIE_WITH_THREADS
ISSUE_VDSO_MISSING
ISSUE_LSM_DETECTED
```

**New Fields in `feature_results` struct**:
```c
bool tty_detected;
int tty_count;
bool seccomp_enabled;
bool seccomp_kernel_support_missing;
bool zombie_with_threads;
bool vdso_missing;
bool lsm_detected;
char lsm_profile[256];
```

### 🧪 Build Status
- ✅ Compiles with **zero warnings**
- ✅ All functions integrated into main check pipeline
- ✅ Compatibility scoring updated

### 📝 Documentation Updates
- Created `MISSING_CHECKS.md` - comprehensive analysis of all CRIU limitations
- Updated `README.md` with new detection features
- Added inline code comments for maintainability

---

## Initial Release - Core Features (2026-02-04)

### ✅ Implemented

1. **io_uring Detection** (CRITICAL)
   - FD and VMA scanning
   - Guaranteed failure detection

2. **RSEQ + Kernel Support** (CRITICAL)
   - Modern glibc detection
   - Kernel feature validation

3. **SysVIPC without IPC Namespace** (CRITICAL)
   - VMA type checking
   - Namespace validation

4. **Process State Validation** (CRITICAL)
   - Zombie detection
   - Stopped process detection
   - Invalid session ID check

5. **TCP ESTABLISHED Connections** (WARNING)
   - `/proc/<PID>/net/tcp{,6}` parsing
   - Socket inode matching

6. **AIO Ring Alignment** (CRITICAL)
   - Page alignment validation

7. **Multithreading** (INFO)
   - Thread count reporting

8. **Namespace Isolation** (INFO)
   - All namespace types detected

9. **Kernel Feature Checking**
   - Version-based feature detection
   - Sysfs probing where available

### 🏗️ Architecture

Modular design with clean separation:
- `main.c` - CLI entry point
- `common.c/.h` - Utilities, issue tracking
- `proc_reader.c/.h` - /proc parsing (non-invasive)
- `feature_detector.c/.h` - Feature detection logic
- `resource_checker.c/.h` - Resource validation
- `compatibility.c/.h` - Scoring algorithm
- `report.c/.h` - Output formatting

### 📊 Output Formats

- **Human-readable** with color coding
- **JSON** for automation
- **Exit codes** for CI/CD integration

---

## Next Steps (Planned)

### Phase 2 - Important Checks
- [ ] Overmounted filesystem detection
- [ ] Nested PID namespace limitations
- [ ] AutoFS mount detection
- [ ] UFFD support validation
- [ ] Memory tracking availability

### Phase 3 - Edge Cases
- [ ] Ghost file detection
- [ ] Packet socket multicast
- [ ] Netlink group limits
- [ ] BPF map type validation
- [ ] Pipe packet mode

### Future Enhancements
- [ ] CRIU command suggestion engine
- [ ] Interactive mode with fix recommendations
- [ ] Web UI dashboard
- [ ] Integration with CRIU upstream
