#!/bin/bash
# CastAI CRIU Bundle Local Builder and Validator
# Build CRIU bundles locally for testing before release
#
# Usage: ./contrib/castai/release/build-local-castai.sh [arch] [version]
#
# Examples:
#   ./contrib/castai/release/build-local-castai.sh           # Auto-detect architecture
#   ./contrib/castai/release/build-local-castai.sh amd64
#   ./contrib/castai/release/build-local-castai.sh arm64 v1.0.0

set -e

# Auto-detect architecture if not provided
detect_arch() {
  local machine
  machine=$(uname -m)
  case "$machine" in
    x86_64)
      echo "amd64"
      ;;
    aarch64)
      echo "arm64"
      ;;
    *)
      echo "amd64" # Default to amd64 if unknown
      ;;
  esac
}

ARCH=${1:-$(detect_arch)}
VERSION=${2:-local}
OUTPUT_DIR="universal-${ARCH}-bins-castai"
TARBALL="criu-castai-${VERSION}-${ARCH}.tar.gz"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Cleanup function
cleanup() {
  echo "Cleaning up old build artifacts..."
  rm -rf "${OUTPUT_DIR}"
  rm -f "${TARBALL}"
}

# Map architecture names
get_elf_machine() {
  case "$1" in
  amd64 | x86_64)
    echo "X86-64"
    ;;
  arm64 | aarch64)
    echo "AArch64"
    ;;
  *)
    echo "Unknown"
    ;;
  esac
}

# Validation function
validate_bundle() {
  local bundle_dir="$1"
  echo ""
  echo "=== Validating CastAI CRIU Bundle ==="

  local failed=0
  local expected_machine
  expected_machine=$(get_elf_machine "$ARCH")

  # Check required files exist
  echo -n "Checking required files... "
  local required_files=(
    "bin/criu"
    "lib/criu/cuda_plugin.so"
  )

  for file in "${required_files[@]}"; do
    if [[ ! -e "${bundle_dir}/${file}" ]]; then
      echo -e "${RED}FAILED${NC}"
      echo -e "  ${RED}✗${NC} Missing: ${file}"
      failed=1
      break
    fi
  done

  if [[ $failed -eq 0 ]]; then
    echo -e "${GREEN}OK${NC}"
  fi

  # Check if binaries are executable
  echo -n "Checking executables... "
  if [[ ! -x "${bundle_dir}/bin/criu" ]]; then
    echo -e "${RED}FAILED${NC}"
    echo -e "  ${RED}✗${NC} bin/criu is not executable"
    failed=1
  else
    echo -e "${GREEN}OK${NC}"
  fi

  # Check RPATH/RUNPATH (MUST PASS for portability)
  echo -n "Checking RPATH/RUNPATH... "
  # Note: Using single quotes to literally match $ORIGIN (not expand as variable)
  # shellcheck disable=SC2016
  if ! readelf -d "${bundle_dir}/bin/criu" 2>/dev/null | grep -qE '(RPATH|RUNPATH).*\$ORIGIN/../lib'; then
    echo -e "${RED}FAILED${NC}"
    # shellcheck disable=SC2016
    echo -e "  ${RED}✗${NC} RPATH/RUNPATH not set to \$ORIGIN/../lib"
    echo "  Current:"
    readelf -d "${bundle_dir}/bin/criu" | grep -E 'RPATH|RUNPATH' || echo "    (none)"
    failed=1
  else
    echo -e "${GREEN}OK${NC}"
  fi

  # ELF Architecture Validation
  echo -n "Validating ELF architecture (${expected_machine})... "
  local arch_errors=0

  for binary in "bin/criu" "lib/criu/cuda_plugin.so"; do
    if [[ -f "${bundle_dir}/${binary}" ]]; then
      local actual_machine
      # Extract full machine string (handles "Advanced Micro Devices X86-64" and "AArch64")
      actual_machine=$(readelf -h "${bundle_dir}/${binary}" 2>/dev/null | grep "Machine:" | sed 's/.*Machine:[[:space:]]*//')

      # Normalize machine name for comparison
      if [[ "$actual_machine" =~ X86-64 ]]; then
        actual_machine="X86-64"
      elif [[ "$actual_machine" =~ AArch64 ]]; then
        actual_machine="AArch64"
      fi

      if [[ "$actual_machine" != "$expected_machine" ]]; then
        if [[ $arch_errors -eq 0 ]]; then
          echo -e "${RED}FAILED${NC}"
        fi
        echo -e "  ${RED}✗${NC} ${binary}: expected ${expected_machine}, got ${actual_machine}"
        arch_errors=1
        failed=1
      fi
    fi
  done

  if [[ $arch_errors -eq 0 ]]; then
    echo -e "${GREEN}OK${NC}"
  fi

  # ELF Type Validation
  echo -n "Validating ELF types... "
  local type_errors=0

  # Check bin/criu is executable (EXEC or DYN)
  local criu_type
  criu_type=$(readelf -h "${bundle_dir}/bin/criu" 2>/dev/null | grep "Type:" | awk '{print $2}')
  if [[ "$criu_type" != "EXEC" && "$criu_type" != "DYN" ]]; then
    if [[ $type_errors -eq 0 ]]; then
      echo -e "${RED}FAILED${NC}"
    fi
    echo -e "  ${RED}✗${NC} bin/criu: expected EXEC or DYN, got ${criu_type}"
    type_errors=1
    failed=1
  fi

  # Check plugin is DYN (shared object)
  for lib in "lib/criu/cuda_plugin.so"; do
    local lib_type
    lib_type=$(readelf -h "${bundle_dir}/${lib}" 2>/dev/null | grep "Type:" | awk '{print $2}')
    if [[ "$lib_type" != "DYN" ]]; then
      if [[ $type_errors -eq 0 ]]; then
        echo -e "${RED}FAILED${NC}"
      fi
      echo -e "  ${RED}✗${NC} ${lib}: expected DYN, got ${lib_type}"
      type_errors=1
      failed=1
    fi
  done

  if [[ $type_errors -eq 0 ]]; then
    echo -e "${GREEN}OK${NC}"
  fi

  # Dynamic Section Validation
  echo -n "Validating dynamic sections... "
  local dyn_errors=0

  # Check bin/criu has NEEDED entries
  if ! readelf -d "${bundle_dir}/bin/criu" 2>/dev/null | grep -q "NEEDED"; then
    if [[ $dyn_errors -eq 0 ]]; then
      echo -e "${RED}FAILED${NC}"
    fi
    echo -e "  ${RED}✗${NC} bin/criu: no NEEDED entries found"
    dyn_errors=1
    failed=1
  fi

  # Check bin/criu has RPATH or RUNPATH
  if ! readelf -d "${bundle_dir}/bin/criu" 2>/dev/null | grep -qE "RPATH|RUNPATH"; then
    if [[ $dyn_errors -eq 0 ]]; then
      echo -e "${RED}FAILED${NC}"
    fi
    echo -e "  ${RED}✗${NC} bin/criu: no RPATH or RUNPATH found"
    dyn_errors=1
    failed=1
  fi

  if [[ $dyn_errors -eq 0 ]]; then
    echo -e "${GREEN}OK${NC}"
  fi

  echo -n "Validating symbol exports... "

  # Check dependencies (only on Linux)
  if [[ "$(uname -s)" == "Linux" ]]; then
    echo -n "Checking dependencies... "
    local missing_deps
    missing_deps=$(ldd "${bundle_dir}/bin/criu" 2>&1 | grep "not found" || true)
    if [[ -n "$missing_deps" ]]; then
      echo -e "${RED}FAILED${NC}"
      echo -e "  ${RED}✗${NC} Missing dependencies:"
      while IFS= read -r line; do
        echo "    $line"
      done <<<"$missing_deps"
      failed=1
    else
      echo -e "${GREEN}OK${NC}"
    fi

    echo -n "Checking libcriu.so resolution... "
    echo -e "${BLUE}SKIP${NC} (criu doesn't depend on libcriu.so)"
  else
    echo -e "${BLUE}SKIP${NC} dependency checks (not on Linux)"
  fi

  # Check plugin is a shared object
  echo -n "Checking plugin format... "
  if ! file "${bundle_dir}/lib/criu/cuda_plugin.so" | grep -q "shared object"; then
    echo -e "${RED}FAILED${NC}"
    echo -e "  ${RED}✗${NC} cuda_plugin.so is not a shared object"
    failed=1
  else
    echo -e "${GREEN}OK${NC}"
  fi

  # Show bundle size
  echo ""
  echo "Bundle size:"
  du -sh "${bundle_dir}"

  # Show detailed file list
  echo ""
  echo "Bundle contents:"
  find "${bundle_dir}" -type f -o -type l | sort | sed 's/^/  /'

  echo ""
  if [[ $failed -eq 0 ]]; then
    echo -e "${GREEN}=== Validation PASSED ===${NC}"
    return 0
  else
    echo -e "${RED}=== Validation FAILED ===${NC}"
    return 1
  fi
}

# Function to ensure multi-arch builder exists
ensure_builder() {
  local builder_name="criu-castai-builder"
  
  echo "Checking for multi-architecture builder..."
  
  # Check if builder exists and supports required platforms
  if docker buildx inspect "$builder_name" &>/dev/null; then
    echo "✓ Using existing builder: $builder_name"
    docker buildx use "$builder_name"
    return 0
  fi
  
  echo "Creating multi-architecture builder..."
  
  # Setup QEMU for cross-platform builds (if not already done)
  echo "  Setting up QEMU for ARM64 emulation..."
  if ! docker run --rm --privileged multiarch/qemu-user-static --reset -p yes &>/dev/null; then
    echo "  ${YELLOW}Warning: Failed to setup QEMU. ARM64 builds may not work.${NC}"
  fi
  
  # Create builder with support for amd64 and arm64
  docker buildx create \
    --name "$builder_name" \
    --driver docker-container \
    --platform linux/amd64,linux/arm64 \
    --use
  
  echo -e "  ${GREEN}✓${NC} Created and activated builder: $builder_name"
}

# Main build process
echo "========================================="
echo "CastAI CRIU Bundle Builder"
echo "========================================="
echo "Arch:    ${ARCH}"
echo "Version: ${VERSION}"
echo "========================================="
echo ""

# Check if Dockerfile exists
DOCKERFILE="contrib/castai/release/Dockerfile.universal-castai"
if [[ ! -f "${DOCKERFILE}" ]]; then
  echo -e "${RED}Error: ${DOCKERFILE} does not exist${NC}"
  exit 1
fi

# Cleanup old builds
cleanup

# Ensure multi-arch builder exists
ensure_builder

# Build using Docker buildx
echo ""
echo "Running Docker build for linux/${ARCH}..."
docker buildx build \
  --platform "linux/${ARCH}" \
  -f "${DOCKERFILE}" \
  --output "${OUTPUT_DIR}" \
  .

echo ""
echo "Build complete. Creating tarball..."

# Create tarball
tar -czf "${TARBALL}" -C "${OUTPUT_DIR}" .

echo -e "${GREEN}✓${NC} Created: ${TARBALL}"

# Validate bundle
if validate_bundle "${OUTPUT_DIR}"; then
  echo ""
  echo -e "${GREEN}✓ Bundle validation passed!${NC}"
  exit_code=0
else
  echo ""
  echo -e "${RED}✗ Bundle validation failed!${NC}"
  exit_code=1
fi

# Usage instructions
echo ""
echo "========================================="
echo "Testing Instructions:"
echo "========================================="
echo "Extract and test:"
echo "  mkdir test-castai && tar -xzf ${TARBALL} -C test-castai"
echo "  test-castai/bin/criu --version"
echo "  test-castai/bin/criu check"
echo ""
echo "Test plugin loading:"
echo "  test-castai/bin/criu dump -t <pid> -D /tmp/test -L \$(pwd)/test-castai/lib/criu"
echo ""
echo "Clean up:"
echo "  rm -rf ${OUTPUT_DIR} ${TARBALL} test-castai"
echo "========================================="

exit $exit_code
