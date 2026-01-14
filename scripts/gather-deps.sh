#!/bin/bash
set -e

# Usage: gather-deps.sh <binary1> [binary2 ...] <output_lib_dir>
# Gathers all shared library dependencies for the given binaries
# and copies them to the output directory.

if [ $# -lt 2 ]; then
	echo "Usage: $0 <binary1> [binary2 ...] <output_lib_dir>"
	exit 1
fi

# Last argument is the output directory
OUTPUT_DIR="${@: -1}"
# All other arguments are binaries
BINARIES=("${@:1:$#-1}")

echo "Gathering dependencies for: ${BINARIES[@]}"
echo "Output directory: $OUTPUT_DIR"

mkdir -p "$OUTPUT_DIR"

# Set to track already copied libraries (to avoid duplicates)
declare -A COPIED_LIBS

# Function to recursively copy dependencies
copy_deps() {
	local binary="$1"

	if [ ! -f "$binary" ]; then
		echo "Warning: $binary not found, skipping"
		return
	fi

	# Get all dependencies using ldd
	ldd "$binary" 2>/dev/null | while read -r line; do
		# Parse ldd output: libname.so => /path/to/libname.so (0xaddress)
		# or: /lib64/ld-linux-x86-64.so.2 (0xaddress)

		# Extract library path
		libpath=$(echo "$line" | grep -oP '=> \K[^ ]+' || echo "$line" | grep -oP '^[[:space:]]*\K/[^ ]+')

		# Skip if no path found or if it's a virtual library
		if [ -z "$libpath" ] || [ "$libpath" = "=>" ] || [[ "$line" =~ "not found" ]]; then
			continue
		fi

		# Skip if not an absolute path
		if [[ ! "$libpath" =~ ^/ ]]; then
			continue
		fi

		# Skip if already copied
		if [ -n "${COPIED_LIBS[$libpath]}" ]; then
			continue
		fi

		# Check if file exists
		if [ ! -f "$libpath" ]; then
			echo "Warning: $libpath not found"
			continue
		fi

		echo "Copying: $libpath"
		cp -L "$libpath" "$OUTPUT_DIR/"
		COPIED_LIBS[$libpath]=1

		# Recursively copy dependencies of this library
		copy_deps "$libpath"
	done
}

# Process each binary
for binary in "${BINARIES[@]}"; do
	echo "Processing $binary..."
	copy_deps "$binary"
done

echo "Done! Dependencies copied to $OUTPUT_DIR"
echo "Total libraries: $(ls -1 "$OUTPUT_DIR" | wc -l)"
