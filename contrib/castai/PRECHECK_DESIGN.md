# CRIU Pre-Check Tool Design

## Goal
Analyze a running process to determine CRIU checkpoint/restore compatibility **WITHOUT** causing downtime (no process freeze, no parasite injection).

## Architecture

### Tool Name: `criu-precheck`

### Location: `contrib/castai/criu-precheck/`

### Design Principles
1. **100% Non-Invasive**: Only reads /proc, no ptrace, no process stopping
2. **Comprehensive**: Checks everything detectable without parasite
3. **Actionable**: Provides specific recommendations and required flags
4. **Confidence Scoring**: Reports likelihood of successful C/R

---

## Implementation Structure

```
contrib/castai/criu-precheck/
├── main.c                    # Entry point, CLI parsing
├── proc_reader.c/.h          # /proc parsing utilities
├── feature_detector.c/.h     # Feature detection (io_uring, rseq, etc.)
├── resource_checker.c/.h     # Resource validation (FDs, VMAs, etc.)
├── namespace_analyzer.c/.h   # Namespace checks
├── network_inspector.c/.h    # Network/socket analysis
├── mount_analyzer.c/.h       # Mountpoint analysis
├── compatibility.c/.h        # Compatibility matrix & scoring
├── report.c/.h               # Output formatting (JSON/human-readable)
└── Makefile
```

---

## Checks Implemented (By Category)

### 1. KERNEL FEATURE VALIDATION
**Method**: Reuse CRIU's `criu check` infrastructure

```c
// Check kernel features required for this workload
check_kernel_features() {
    run_criu_check("--all");
    parse_output();
    report_missing_features();
}
```

**Checks**:
- All Category 1 features (core requirements)
- Category 2 features (based on detected workload needs)
- RSEQ kernel support (critical: has_rseq + has_ptrace_get_rseq_conf)
- Memory tracking (if --track-mem needed)
- Network features (if sockets detected)
- Namespace support (based on process namespaces)

### 2. PROCESS STATE CHECKS
**Source**: `/proc/<PID>/stat`, `/proc/<PID>/status`

```c
struct process_state {
    int pid;
    int ppid;
    int pgid;
    int sid;
    char state;          // R, S, D, Z, T, etc.
    int num_threads;
    bool is_leader;      // pid == sid (session leader)
    bool is_zombie;
};

check_process_state(int pid) {
    // Read /proc/PID/stat
    // Validate: state != 'Z' (not zombie)
    // Validate: state != 'T' (not stopped - unsupported)
    // Validate: sid != 0 (valid session)
    // Check if session leader exists
}
```

**Detectable Issues**:
- ✅ Process is zombie
- ✅ Process is stopped (TASK_STOPPED - unsupported)
- ✅ Invalid session ID (sid == 0)
- ✅ Session leader outside PID namespace

### 3. MEMORY MAPPING ANALYSIS
**Source**: `/proc/<PID>/smaps`, `/proc/<PID>/maps`

```c
struct vma_info {
    unsigned long start;
    unsigned long end;
    unsigned long size;
    int prot;           // PROT_READ|WRITE|EXEC
    int flags;          // MAP_SHARED|PRIVATE|ANONYMOUS
    char *pathname;     // Mapped file path
    int vma_type;       // REGULAR, SYSVIPC, SOCKET, AIORING
};

check_memory_mappings(int pid) {
    parse_smaps(pid, &vmas);

    for each vma:
        // Detect VMA types
        if (path == "anon_inode:[aio]") {
            vma.type = VMA_AIORING;
            check_aio_compatibility();
        }
        if (path contains "SYSV") {
            vma.type = VMA_SYSVIPC;
            check_ipc_namespace_required();
        }
        if (path == "socket:") {
            vma.type = VMA_SOCKET;
        }

        // Check alignment
        if (vma.type == VMA_AIORING && (vma.size % PAGE_SIZE != 0)) {
            WARN("AIO ring misaligned - will fail");
        }

        // Detect VDSO
        if (path == "[vdso]") {
            check_vdso_support();
        }

        // Detect executable
        if (prot & PROT_EXEC && vma.start == exe_start) {
            vma.is_executable = true;
        }
}
```

**Detectable Issues**:
- ✅ AIO rings detected (io_uring usage)
- ✅ AIO ring misalignment (will cause dump failure)
- ✅ SysVIPC shared memory (requires IPC namespace check)
- ✅ Socket memory mappings
- ✅ VDSO presence and mappability
- ✅ Total private page count (memory dump size estimate)
- ⚠️ Executable text segment boundaries (for reference)

### 4. FILE DESCRIPTOR ANALYSIS
**Source**: `/proc/<PID>/fd/`, `/proc/<PID>/fdinfo/<FD>`

```c
struct fd_info {
    int fd_num;
    char *type;         // "reg", "sock", "pipe", "eventfd", etc.
    char *target;       // Symlink target
    int flags;          // From fdinfo: flags, pos
    bool is_io_uring;   // Detected from fdinfo
    bool is_epoll;
    bool is_socket;
    int socket_type;    // INET, INET6, UNIX, NETLINK, etc.
};

check_file_descriptors(int pid) {
    list_fds(pid, &fds);

    for each fd:
        // Read symlink
        readlink(sprintf("/proc/%d/fd/%d", pid, fd), target);

        // Parse fdinfo
        fdinfo = parse_fdinfo(pid, fd);

        // Detect types
        if (target.startswith("socket:")) {
            fd.is_socket = true;
            detect_socket_type_from_net_proc(pid, extract_inode(target));
        }
        if (target == "anon_inode:[eventfd]") {
            fd.type = "eventfd";
        }
        if (target == "anon_inode:[io_uring]") {
            fd.is_io_uring = true;
            CRITICAL("io_uring detected - requires --skip-io-uring or may fail");
        }
        if (target == "anon_inode:[eventpoll]") {
            fd.is_epoll = true;
        }
        if (target.startswith("/dev/")) {
            check_device_checkpoint_support(target);
        }
        if (target.startswith("/")) {
            // Regular file
            check_file_accessibility(target);
            check_if_external_mount(pid, target);
        }
}
```

**Detectable Issues**:
- ✅ **io_uring FDs detected** - Major compatibility issue!
- ✅ Socket FDs (requires network checkpoint)
- ✅ Epoll FDs (requires event tracking)
- ✅ Eventfd, signalfd, timerfd, pidfd (requires kernel features)
- ✅ TTY/PTY devices (requires TTY support)
- ✅ Device files (requires device checkpoint support)
- ✅ Regular files on external filesystems (may need --external)
- ✅ FD count > ulimit (requires rlimit adjustment)

### 5. NETWORK/SOCKET INSPECTION
**Source**: `/proc/<PID>/net/{tcp,udp,unix,netlink,packet}`, `/proc/<PID>/fd/`

```c
struct socket_info {
    int inode;
    char *type;         // "TCP", "UDP", "UNIX", "NETLINK", "PACKET"
    char *state;        // "ESTABLISHED", "LISTEN", "CLOSE_WAIT", etc.
    char *local_addr;
    char *remote_addr;
    int local_port;
    int remote_port;
    bool requires_repair; // TCP requires TCP_REPAIR mode
};

check_network_resources(int pid) {
    // Parse /proc/PID/net/tcp, tcp6
    tcp_sockets = parse_proc_net_tcp(pid);
    for each sock:
        if (sock.state == "ESTABLISHED") {
            WARN("Active TCP connection - requires --tcp-established");
            check_kernel_feature("tcp_repair");
        }
        if (sock.state == "LISTEN") {
            INFO("Listening TCP socket");
        }
        if (sock.state == "CLOSE_WAIT") {
            check_kernel_feature("tcp_half_closed");
        }

    // Parse /proc/PID/net/unix
    unix_sockets = parse_proc_net_unix(pid);
    for each sock:
        if (sock.type == "STREAM" && sock.state == "CONNECTED") {
            WARN("Connected UNIX socket - may need external handling");
        }

    // Parse /proc/PID/net/udp
    udp_sockets = parse_proc_net_udp(pid);

    // Parse /proc/PID/net/netlink
    netlink_sockets = parse_proc_net_netlink(pid);

    // Parse /proc/PID/net/packet
    packet_sockets = parse_proc_net_packet(pid);
    if (packet_sockets.count > 0) {
        check_kernel_feature("packet_diag");
    }
}
```

**Detectable Issues**:
- ✅ TCP connections (ESTABLISHED, LISTEN, CLOSE_WAIT)
- ✅ UDP sockets
- ✅ UNIX domain sockets (connected pairs need tracking)
- ✅ Netlink sockets
- ✅ Packet sockets (raw sockets)
- ✅ Network namespace usage
- ⚠️ TCP connection state (may need TCP_REPAIR)

### 6. NAMESPACE ANALYSIS
**Source**: `/proc/<PID>/ns/*`, `/proc/<PID>/mountinfo`

```c
struct namespace_info {
    ino_t mnt_ns;
    ino_t net_ns;
    ino_t ipc_ns;
    ino_t uts_ns;
    ino_t pid_ns;
    ino_t user_ns;
    ino_t cgroup_ns;
    ino_t time_ns;
    bool in_default_ns[8]; // Compare with init_ns
};

check_namespaces(int pid) {
    for each ns_type in [mnt, net, ipc, uts, pid, user, cgroup, time]:
        readlink(sprintf("/proc/%d/ns/%s", pid, ns_type), &ns_id);
        readlink(sprintf("/proc/1/ns/%s", ns_type), &init_ns_id);

        if (ns_id != init_ns_id) {
            ns_info[ns_type].isolated = true;

            // Check kernel support
            check_kernel_feature(sprintf("%sns", ns_type));
        }

    // Special checks
    if (ns_info.ipc_ns.isolated) {
        // SysVIPC mappings are OK
    } else if (has_sysvipc_vma) {
        ERROR("SysVIPC memory without IPC namespace - WILL FAIL");
    }

    if (ns_info.time_ns.isolated) {
        check_kernel_feature("timens");
    }
}
```

**Detectable Issues**:
- ✅ SysVIPC memory without IPC namespace (CRITICAL FAILURE)
- ✅ Namespace isolation detected
- ✅ Missing kernel namespace support
- ✅ User namespace UID/GID mapping requirements
- ✅ Time namespace requirements

### 7. MOUNT POINT ANALYSIS
**Source**: `/proc/<PID>/mountinfo`, `/proc/<PID>/cwd`, `/proc/<PID>/root`

```c
struct mount_info {
    int mnt_id;
    int parent_id;
    char *dev;
    char *root;
    char *mount_point;
    char *fs_type;
    char *options;
    bool is_external;   // Not in root NS
    bool is_bind;
    bool is_shared;
};

check_mounts(int pid) {
    parse_mountinfo(pid, &mounts);

    for each mount:
        // Detect external mounts
        if (mount.fs_type in ["nfs", "cifs", "fuse"]) {
            WARN("External filesystem %s - may need --external", mount.fs_type);
        }

        // Check bind mounts
        if (mount.root != "/") {
            mount.is_bind = true;
        }

        // Check shared mounts
        if (mount.options contains "shared:") {
            mount.is_shared = true;
        }

    // Check cwd and root accessibility
    cwd = readlink(sprintf("/proc/%d/cwd", pid));
    root = readlink(sprintf("/proc/%d/root", pid));

    if (!is_accessible(cwd)) {
        ERROR("CWD not accessible from C/R context");
    }
}
```

**Detectable Issues**:
- ✅ External filesystems (NFS, CIFS, FUSE)
- ✅ Bind mounts
- ✅ Shared mounts (propagation issues)
- ✅ Mount namespace complexity
- ✅ CWD/root accessibility

### 8. RSEQ DETECTION
**Source**: `/proc/<PID>/maps` (look for rseq library usage)

```c
check_rseq_usage(int pid) {
    // RSEQ is transparent - can't directly detect from /proc
    // But we can check:

    // 1. Kernel support
    if (!kernel_has_rseq) {
        return; // No RSEQ possible
    }

    // 2. glibc version (glibc 2.35+ uses RSEQ)
    check_mapped_libs(pid);
    if (has_glibc_version >= 2.35) {
        WARN("glibc 2.35+ detected - process likely uses RSEQ");

        // Check critical kernel feature
        if (!kernel_has_ptrace_get_rseq_conf) {
            ERROR("Kernel lacks PTRACE_GET_RSEQ_CONFIGURATION - RSEQ dump WILL FAIL");
        }
    }

    // 3. Check if rseq.h is linked
    if (grep_maps(pid, "librseq")) {
        WARN("librseq detected - RSEQ in use");
    }
}
```

**Detectable Issues**:
- ⚠️ RSEQ likely in use (glibc 2.35+)
- ✅ Kernel lacks PTRACE_GET_RSEQ_CONFIGURATION (CRITICAL if RSEQ used)

### 9. TIMER ANALYSIS
**Source**: `/proc/<PID>/timers`

```c
struct timer_info {
    int id;
    char *signal;
    char *notify;
    int clockid;
};

check_timers(int pid) {
    parse_timers(pid, &timers);

    if (timers.count > 0) {
        check_kernel_feature("timerfd");
        INFO("%d POSIX timers detected", timers.count);
    }
}
```

**Detectable Issues**:
- ✅ POSIX timer count
- ✅ Timerfd kernel support

### 10. CGROUP ANALYSIS
**Source**: `/proc/<PID>/cgroup`

```c
check_cgroups(int pid) {
    parse_cgroups(pid, &cgroups);

    for each cgroup:
        if (cgroup.hierarchy == 0) {
            // cgroupv2
            check_kernel_feature("cgroupv2");
        }

        // Check if cgroup is accessible
        if (!exists(cgroup.path)) {
            WARN("Cgroup path not accessible: %s", cgroup.path);
        }
}
```

**Detectable Issues**:
- ✅ Cgroup v2 usage
- ✅ Cgroup path accessibility

### 11. SECURITY MODULE CHECKS
**Source**: `/proc/<PID>/attr/{current,exec,fscreate,keycreate,sockcreate}`

```c
check_lsm(int pid) {
    // AppArmor
    current = read_file(sprintf("/proc/%d/attr/current", pid));
    if (current) {
        INFO("AppArmor profile: %s", current);
        check_kernel_feature("apparmor_stacking");
    }

    // SELinux
    if (file_exists("/sys/fs/selinux")) {
        WARN("SELinux detected - profile checkpoint required");
    }
}
```

**Detectable Issues**:
- ✅ AppArmor profile detection
- ✅ SELinux usage
- ✅ LSM dumping requirements

### 12. THREAD ANALYSIS
**Source**: `/proc/<PID>/task/`, `/proc/<PID>/status`

```c
check_threads(int pid) {
    threads = list_dir(sprintf("/proc/%d/task", pid));

    num_threads = threads.count;
    INFO("%d threads detected", num_threads);

    // Check if multithreaded
    if (num_threads > 1) {
        check_kernel_feature("ptrace_seize_multi");
    }

    // Note: Thread-local info requires parasite
    WARN("Thread-local storage, TLS, robust lists require parasite dump");
}
```

**Detectable Issues**:
- ✅ Thread count
- ⚠️ Multithreading detected (requires ptrace for all threads)

---

## Output Format

### 1. Human-Readable Summary

```
CRIU Pre-Check Report for PID 12345
====================================

PROCESS INFO:
  Command:     /usr/bin/myapp
  State:       Running (S)
  Threads:     4
  Session:     12340 (valid)

COMPATIBILITY: 78% Likely to Succeed
  ✅ PASSED: 45 checks
  ⚠️  WARNINGS: 3 checks
  ❌ FAILED: 1 check

CRITICAL ISSUES:
  ❌ io_uring detected (FD 5: anon_inode:[io_uring])
     → RECOMMENDATION: Use --skip-io-uring or close io_uring before dump

WARNINGS:
  ⚠️  Active TCP connection (ESTABLISHED 192.168.1.100:8080)
     → RECOMMENDATION: Use --tcp-established flag

  ⚠️  External NFS mount detected: /mnt/shared
     → RECOMMENDATION: Use --external mnt[nfs]:/mnt/shared

  ⚠️  glibc 2.35+ detected - RSEQ likely in use
     → CHECK: Kernel supports PTRACE_GET_RSEQ_CONFIGURATION ✅

RESOURCE SUMMARY:
  Memory:
    - VMAs: 156
    - Private pages: ~245 MB
    - Shared pages: ~89 MB
    - AIO rings: 1 (io_uring)

  File Descriptors: 24
    - Regular files: 8
    - Sockets: 12 (4 TCP, 6 UNIX, 2 UDP)
    - Special: 4 (eventfd, timerfd, epoll, io_uring)

  Network:
    - TCP ESTABLISHED: 1
    - TCP LISTEN: 3
    - UNIX STREAM: 6

  Namespaces:
    - PID namespace: isolated (4026532xxx)
    - Network namespace: isolated (4026532yyy)
    - Mount namespace: isolated (4026532zzz)
    - IPC, UTS, Cgroup: default

RECOMMENDED DUMP COMMAND:
  sudo criu dump -t 12345 \
    --images-dir /tmp/checkpoint \
    --tcp-established \
    --external mnt[nfs]:/mnt/shared \
    --skip-io-uring \
    -v4 --log-file dump.log

KERNEL FEATURES REQUIRED:
  ✅ tcp_repair (for TCP connections)
  ✅ ptrace_get_rseq_conf (for RSEQ)
  ✅ userns (for user namespace)
  ⚠️  uffd (optional, for lazy pages)
```

### 2. JSON Output (--json flag)

```json
{
  "pid": 12345,
  "timestamp": "2026-02-04T10:30:00Z",
  "process": {
    "command": "/usr/bin/myapp",
    "state": "S",
    "ppid": 1,
    "pgid": 12340,
    "sid": 12340,
    "threads": 4,
    "is_zombie": false,
    "is_stopped": false
  },
  "compatibility": {
    "score": 78,
    "level": "likely",
    "passed": 45,
    "warnings": 3,
    "failed": 1
  },
  "issues": {
    "critical": [
      {
        "type": "io_uring_detected",
        "severity": "critical",
        "description": "io_uring detected (FD 5: anon_inode:[io_uring])",
        "recommendation": "Use --skip-io-uring or close io_uring before dump",
        "affected_resource": "fd:5"
      }
    ],
    "warnings": [
      {
        "type": "tcp_established",
        "severity": "warning",
        "description": "Active TCP connection (ESTABLISHED 192.168.1.100:8080)",
        "recommendation": "Use --tcp-established flag"
      }
    ]
  },
  "resources": {
    "memory": {
      "vmas": 156,
      "private_pages_mb": 245,
      "shared_pages_mb": 89,
      "aio_rings": 1
    },
    "file_descriptors": {
      "total": 24,
      "regular": 8,
      "sockets": 12,
      "special": 4,
      "io_uring": 1
    },
    "network": {
      "tcp_established": 1,
      "tcp_listen": 3,
      "unix_stream": 6,
      "udp": 2
    },
    "namespaces": {
      "pid": {"isolated": true, "inode": 4026532123},
      "net": {"isolated": true, "inode": 4026532124},
      "mnt": {"isolated": true, "inode": 4026532125}
    }
  },
  "kernel_features": {
    "required": [
      {"name": "tcp_repair", "available": true},
      {"name": "ptrace_get_rseq_conf", "available": true},
      {"name": "userns", "available": true}
    ],
    "optional": [
      {"name": "uffd", "available": false}
    ]
  },
  "recommended_command": "sudo criu dump -t 12345 --images-dir /tmp/checkpoint --tcp-established --external mnt[nfs]:/mnt/shared --skip-io-uring -v4 --log-file dump.log"
}
```

---

## Confidence Scoring Algorithm

```c
int calculate_confidence_score(struct precheck_results *results) {
    int score = 100;

    // Critical failures
    for each critical_issue:
        if (issue.type == IO_URING_DETECTED) score -= 50;
        if (issue.type == RSEQ_NO_KERNEL_SUPPORT) score -= 100; // Guaranteed fail
        if (issue.type == SYSVIPC_NO_IPC_NS) score -= 100; // Guaranteed fail
        if (issue.type == INVALID_SESSION) score -= 100;
        if (issue.type == ZOMBIE_PROCESS) score -= 100;
        if (issue.type == STOPPED_PROCESS) score -= 80;

    // Warnings
    for each warning:
        if (warning.type == TCP_ESTABLISHED) score -= 5;
        if (warning.type == EXTERNAL_MOUNT) score -= 5;
        if (warning.type == RSEQ_LIKELY) score -= 3;
        if (warning.type == MULTITHREADED) score -= 2;

    // Missing kernel features
    for each missing_feature:
        if (feature.required) score -= 30;
        if (feature.optional) score -= 5;

    return max(0, score);
}

const char* get_confidence_level(int score) {
    if (score >= 90) return "very_likely";
    if (score >= 70) return "likely";
    if (score >= 40) return "uncertain";
    return "unlikely";
}
```

---

## CLI Interface

```bash
# Basic usage
criu-precheck -t <PID>

# JSON output
criu-precheck -t <PID> --json

# Verbose mode
criu-precheck -t <PID> -v

# Check specific aspects only
criu-precheck -t <PID> --check-network
criu-precheck -t <PID> --check-memory
criu-precheck -t <PID> --check-namespaces

# Output to file
criu-precheck -t <PID> -o report.txt
criu-precheck -t <PID> --json -o report.json

# Suggest CRIU command
criu-precheck -t <PID> --suggest-command

# Integration mode (exit code only)
criu-precheck -t <PID> --exit-code-only
# Exit codes:
#   0 = Very likely to succeed (90%+)
#   1 = Likely to succeed (70-89%)
#   2 = Uncertain (40-69%)
#   3 = Unlikely to succeed (<40%)
#   4 = Guaranteed to fail (critical issue detected)
```

---

## Implementation Phases

### Phase 1: Core Infrastructure (Week 1)
- [ ] Project structure setup
- [ ] /proc parsing library (proc_reader.c)
- [ ] Basic CLI parsing (main.c)
- [ ] Kernel feature checking (reuse criu check)

### Phase 2: Resource Detection (Week 2)
- [ ] Memory mapping analysis (resource_checker.c)
- [ ] File descriptor analysis
- [ ] Process state validation
- [ ] Thread counting

### Phase 3: Feature Detection (Week 3)
- [ ] io_uring detection (feature_detector.c)
- [ ] RSEQ detection and validation
- [ ] Network/socket inspection (network_inspector.c)
- [ ] Namespace analysis (namespace_analyzer.c)

### Phase 4: Advanced Analysis (Week 4)
- [ ] Mount point analysis (mount_analyzer.c)
- [ ] Cgroup validation
- [ ] LSM profile detection
- [ ] Timer analysis

### Phase 5: Reporting & Scoring (Week 5)
- [ ] Compatibility scoring (compatibility.c)
- [ ] Human-readable output (report.c)
- [ ] JSON output format
- [ ] Command suggestion engine

### Phase 6: Testing & Integration (Week 6)
- [ ] Unit tests for each module
- [ ] Integration tests with real workloads
- [ ] Documentation
- [ ] CI/CD integration

---

## Testing Strategy

### Test Cases:

1. **Simple stateless process**: `sleep 1000`
   - Expected: 95%+ confidence, no warnings

2. **io_uring application**: Rust tokio app
   - Expected: <50% confidence, critical io_uring warning

3. **TCP server**: nginx
   - Expected: 70-80% confidence, TCP warnings

4. **Containerized app**: Docker container
   - Expected: 75-85% confidence, namespace warnings

5. **glibc 2.35+ app**: Modern systemd service
   - Expected: 80-90% confidence, RSEQ warning (if kernel lacks support)

6. **Multi-namespace app**: Complex container
   - Expected: 70-85% confidence, multiple namespace warnings

7. **NFS-mounted app**: App using /mnt/nfs
   - Expected: 70-85% confidence, external mount warning

8. **STOPPED process**: kill -STOP <PID>
   - Expected: 0% confidence, critical error

9. **Zombie process**: orphaned child
   - Expected: 0% confidence, critical error

---

## Dependencies

### Build Dependencies:
- gcc/clang
- make
- pkg-config

### Runtime Dependencies:
- Linux kernel 3.11+ (minimum CRIU requirement)
- Access to /proc filesystem
- Optional: `criu` binary (for kernel feature checking)

### Libraries:
- libc (standard library)
- No external dependencies (pure C implementation)

---

## Future Enhancements

1. **Integration with CRIU**:
   - Add `criu pre-dump --dry-run` mode
   - Upstream as official CRIU feature

2. **Machine Learning**:
   - Train model on successful/failed dumps
   - Improve confidence scoring

3. **Continuous Monitoring**:
   - Daemon mode: monitor process evolution
   - Alert when incompatible resources are acquired

4. **Web UI**:
   - Visual compatibility dashboard
   - Interactive resource explorer

5. **Cloud Integration**:
   - Kubernetes admission webhook
   - Automatic workload classification

---

## Success Criteria

1. **100% non-invasive**: No process freeze, no ptrace, no parasite
2. **95%+ accuracy**: Confidence score correlates with actual dump success
3. **<1s execution time**: Fast enough for pre-flight checks
4. **Comprehensive coverage**: Checks 90%+ of dump failure scenarios
5. **Actionable output**: Clear recommendations for fixing issues
