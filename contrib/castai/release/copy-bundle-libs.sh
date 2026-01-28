#!/bin/bash
# Common script to copy required libraries for CRIU CastAI bundles
# This script is sourced by Dockerfiles to avoid duplication
#
# Expected environment variables:
#   BUNDLE_DIR: Target directory for the bundle (e.g., /bundle-castai)
#   LIB_SOURCE_PATHS: Space-separated list of library source directories
#
# Usage in Dockerfile:
#   ENV BUNDLE_DIR=/bundle-castai LIB_SOURCE_PATHS="/build-lib /build-lib64 /build-usr-lib64"
#   COPY copy-bundle-libs.sh /tmp/
#   RUN bash /tmp/copy-bundle-libs.sh

set -e

if [ -z "$BUNDLE_DIR" ]; then
  echo "Error: BUNDLE_DIR not set"
  exit 1
fi

if [ -z "$LIB_SOURCE_PATHS" ]; then
  echo "Error: LIB_SOURCE_PATHS not set"
  exit 1
fi

echo "=== Copying required libraries to $BUNDLE_DIR/lib ==="

# Function to copy library files (handles symlinks and actual files)
copy_lib() {
  local lib_pattern="$1"
  local found=0

  for src_dir in $LIB_SOURCE_PATHS; do
    for lib in "$src_dir"/$lib_pattern; do
      if [ -e "$lib" ]; then
        cp -v "$lib" "$BUNDLE_DIR/lib/" 2>/dev/null || true
        found=1
      fi
    done
  done

  if [ $found -eq 0 ]; then
    echo "  Warning: $lib_pattern not found in any source path"
  fi
}

# Copy direct CRIU dependencies
echo "Copying direct dependencies..."
copy_lib "libprotobuf-c.so.1*"
copy_lib "libnet.so.1*"
copy_lib "libpcap.so.1*"
copy_lib "libcap.so.*"
copy_lib "libaio.so.*"
copy_lib "libbsd.so.*"
copy_lib "libgnutls.so.*"
copy_lib "libnftables.so.*"
copy_lib "libnl-3.so.*"
copy_lib "libnl-route-3.so.*"
copy_lib "libuuid.so.1*"
copy_lib "libibverbs.so.*"

# Copy transitive dependencies (libraries that the above depend on)
echo "Copying transitive dependencies..."
copy_lib "libmd.so.*"
copy_lib "libp11-kit.so.*"
copy_lib "libidn2.so.*"
copy_lib "libunistring.so.*"
copy_lib "libtasn1.so.*"
copy_lib "libnettle.so.*"
copy_lib "libhogweed.so.*"
copy_lib "libgmp.so.*"
copy_lib "libffi.so.*"
copy_lib "libjansson.so.*"
copy_lib "libedit.so.*"
copy_lib "libncursesw.so.*"
copy_lib "libncurses.so.*"
copy_lib "libmnl.so.*"
copy_lib "libnftnl.so.*"
copy_lib "libxtables.so.*"

echo "=== Library copying complete ==="
echo ""
echo "Setting RPATH on bundled libraries..."

# Set RPATH on all bundled libraries to look in the same directory
# We only set RPATH on actual .so files, not symlinks
for lib in "$BUNDLE_DIR"/lib/*.so.*; do
  if [ -f "$lib" ] && [ ! -L "$lib" ]; then
    echo "  Setting RPATH on $(basename "$lib")"
    patchelf --set-rpath '$ORIGIN' "$lib" || true
  fi
done

echo "=== RPATH setting complete ==="
