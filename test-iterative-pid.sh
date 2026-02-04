#!/bin/bash

#
# Simple iterative dump/restore test for an existing process
# Useful for quick manual testing with any process PID
# Supports page server mode for remote image transfer testing
#

set -e

# Defaults
NRSNAP=3
SPAUSE=2
PORT=12345
USE_PAGE_SERVER=0
IMGDIR="dump"
VERBOSE=4
PID=""
SHELL_JOB=0

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

function usage {
    cat << EOF
Usage: $0 -t PID [OPTIONS]

Simple iterative checkpoint for testing with any process.

REQUIRED:
    -t PID          Target process ID

OPTIONS:
    -h              Show this help message
    -s              Enable page server mode
    -n NUM          Number of iterations (default: $NRSNAP)
    -p SECONDS      Pause between dumps (default: $SPAUSE)
    -P PORT         Page server port (default: $PORT)
    -d DIR          Image directory (default: $IMGDIR)
    -v LEVEL        Verbosity level 1-4 (default: $VERBOSE)
    -j              Add --shell-job flag (for shell background jobs)
    -r              Restore after final dump

EXAMPLES:
    # Dump a background sleep process
    sleep 1000 &
    $0 -t \$! -j -n 3

    # With page server (recommended for testing)
    $0 -t 12345 -s -n 3

    # With page server and automatic restore
    $0 -t 12345 -s -r

    # Custom settings with page server
    $0 -t 12345 -s -n 5 -p 3 -v 4 -d /tmp/my-dump -P 54321
EOF
    exit 0
}

function log_info {
    echo -e "${GREEN}[INFO]${NC} $@"
}

function log_error {
    echo -e "${RED}[ERROR]${NC} $@"
}

function log_warn {
    echo -e "${YELLOW}[WARN]${NC} $@"
}

function cleanup {
    # Kill page server if running
    if [ -n "$PS_PID" ] && kill -0 $PS_PID 2>/dev/null; then
        log_info "Stopping page server (PID $PS_PID)"
        kill $PS_PID 2>/dev/null || true
        wait $PS_PID 2>/dev/null || true
    fi

    chmod -R a+rw "$IMGDIR" 2>/dev/null || true
}

function fail {
    log_error "$@"
    cleanup
    exit 1
}

DO_RESTORE=0

# Set up cleanup trap
trap cleanup EXIT INT TERM

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -h|--help) usage ;;
        -t|--pid) PID="$2"; shift 2 ;;
        -s|--page-server) USE_PAGE_SERVER=1; shift ;;
        -n|--num) NRSNAP="$2"; shift 2 ;;
        -p|--pause) SPAUSE="$2"; shift 2 ;;
        -P|--port) PORT="$2"; shift 2 ;;
        -d|--dir) IMGDIR="$2"; shift 2 ;;
        -v|--verbose) VERBOSE="$2"; shift 2 ;;
        -j|--shell-job) SHELL_JOB=1; shift ;;
        -r|--restore) DO_RESTORE=1; shift ;;
        *) log_error "Unknown option: $1"; usage ;;
    esac
done

# Validate
if [ -z "$PID" ]; then
    log_error "PID is required (-t option)"
    usage
fi

if ! kill -0 $PID 2>/dev/null; then
    fail "Process $PID does not exist or is not accessible"
fi

CRIU=./amd64-bins/criu
if [ ! -x "$CRIU" ]; then
    fail "CRIU binary not found: $CRIU"
fi

# Create absolute path for IMGDIR
IMGDIR=$(readlink -f "$IMGDIR")

log_info "Configuration:"
log_info "  PID: $PID"
log_info "  Iterations: $NRSNAP"
log_info "  Pause: ${SPAUSE}s"
log_info "  Page server: $([ $USE_PAGE_SERVER -eq 1 ] && echo "enabled (port $PORT)" || echo 'disabled')"
log_info "  Image dir: $IMGDIR"
log_info "  Verbosity: $VERBOSE"
log_info "  Shell job: $([ $SHELL_JOB -eq 1 ] && echo 'yes' || echo 'no')"

# Prepare
rm -rf "$IMGDIR"
mkdir -p "$IMGDIR"

# Shell job flag
SHELL_FLAG=""
[ $SHELL_JOB -eq 1 ] && SHELL_FLAG="--shell-job"

# Iterative dumps
for SNAP in $(seq 1 $NRSNAP); do
    sleep $SPAUSE

    log_info "Iteration $SNAP/$NRSNAP"

    SNAP_DIR="${IMGDIR}/${SNAP}"
    mkdir -p "$SNAP_DIR"

    # Determine command
    if [ $SNAP -eq 1 ]; then
        cmd="pre-dump"
        args="--track-mem -R"
        desc="Initial pre-dump"
    elif [ $SNAP -eq $NRSNAP ]; then
        cmd="dump"
        args="--prev-images-dir=../$((SNAP - 1))/ --track-mem $SHELL_FLAG"
        desc="Final dump"
    else
        cmd="pre-dump"
        args="--prev-images-dir=../$((SNAP - 1))/ --track-mem -R"
        desc="Pre-dump $SNAP"
    fi

    log_info "  $desc"

    # Page server
    PS_PID=""
    ps_args=""
    if [ $USE_PAGE_SERVER -eq 1 ]; then
        log_info "  Starting page server on port $PORT"
        ${CRIU} page-server \
            -D "${SNAP_DIR}/" \
            -o ps.log \
            --auto-dedup \
            --port ${PORT} \
            -v${VERBOSE} &
        PS_PID=$!

        # Give page server time to start and verify it's running
        sleep 0.5

        if ! kill -0 $PS_PID 2>/dev/null; then
            PS_PID=""
            fail "Page server failed to start (see ${SNAP_DIR}/ps.log)"
        fi

        ps_args="--page-server --address 127.0.0.1 --port=${PORT}"
        log_info "  Page server started (PID: $PS_PID)"
    fi

    # Dump
    log_info "  Running: $cmd"
    ${CRIU} $cmd -D "${SNAP_DIR}/" -o dump.log -t ${PID} -v${VERBOSE} $args $ps_args || \
        fail "${cmd} failed at iteration $SNAP (see ${SNAP_DIR}/dump.log)"

    # Wait for page server to finish
    if [ $USE_PAGE_SERVER -eq 1 ] && [ -n "$PS_PID" ]; then
        log_info "  Waiting for page server to finish"
        wait $PS_PID || log_warn "Page server exited with non-zero status"
        PS_PID=""
    fi

    log_info "  ✓ Iteration $SNAP complete"

    # Show memory stats if available
    if [ -f "${SNAP_DIR}/stats-dump" ]; then
        pages_written=$(crit show "${SNAP_DIR}/stats-dump" |  jq ".entries[0].dump".pages_written  )
        log_info "    Stats: pages_written: $pages_written"
    fi
done

log_info "All iterations complete!"
log_info "Images saved in: $IMGDIR"

if [ $USE_PAGE_SERVER -eq 1 ]; then
    log_info "Page server mode was used for all iterations"
fi

# Restore if requested
if [ $DO_RESTORE -eq 1 ]; then
    log_info "Restoring process..."
    FINAL_DIR="${IMGDIR}/${NRSNAP}"

    ${CRIU} restore -D "${FINAL_DIR}/" -o restore.log -d -v${VERBOSE} $SHELL_FLAG || \
        fail "Restore failed"

    log_info "✓ Restore complete"
else
    log_info ""
    log_info "To restore manually, run:"
    echo "  ${CRIU} restore -D ${IMGDIR}/${NRSNAP}/ -d -v4 $SHELL_FLAG"
fi

log_info "${GREEN}SUCCESS${NC}"
