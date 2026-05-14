// clear-refs-exec.go
//
// A utility to clear soft-dirty bits for a containerized process by executing
// clear_refs inside the container via crictl exec.
//
// Build: CGO_ENABLED=0 go build -ldflags="-s -w" -o clear-refs-exec clear-refs-exec.go

package main

import (
	"bufio"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
)

func main() {
	// Parse command-line flags
	clearRefsBin := flag.String("clear-refs-bin", "/bin/clear_refs", "path to clear_refs binary inside container")
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: %s [options] <root-ns-pid>\n\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "Clears soft-dirty bits for a container process via crictl exec.\n\n")
		fmt.Fprintf(os.Stderr, "Options:\n")
		flag.PrintDefaults()
	}
	flag.Parse()

	if flag.NArg() != 1 {
		flag.Usage()
		os.Exit(1)
	}

	pid := flag.Arg(0)

	// Validate PID is a number
	if _, err := strconv.Atoi(pid); err != nil {
		fmt.Fprintf(os.Stderr, "error: invalid PID %q: %v\n", pid, err)
		os.Exit(1)
	}

	// Extract container ID from cgroup
	containerID, err := getContainerID(pid)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: failed to get container ID: %v\n", err)
		os.Exit(1)
	}

	// Get the NSpid (PID in container namespace)
	nspid, err := getNsPid(pid)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: failed to get NSpid: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Container ID: %s\n", containerID)
	fmt.Printf("NSpid: %s\n", nspid)

	// Execute clear_refs inside the container via crictl exec
	if err := execClearRefs(containerID, *clearRefsBin, nspid); err != nil {
		fmt.Fprintf(os.Stderr, "error: failed to execute clear_refs: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("Successfully cleared soft-dirty bits")
}

// getContainerID reads /proc/<pid>/cgroup and extracts the container ID.
// Handles both standard kubepods format and cri-containerd scope format.
func getContainerID(pid string) (string, error) {
	cgroupPath := filepath.Join("/proc", pid, "cgroup")
	file, err := os.Open(cgroupPath)
	if err != nil {
		return "", fmt.Errorf("failed to open %s: %w", cgroupPath, err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		// cgroup line format: hierarchy-ID:controller-list:cgroup-path
		// Example: 0::/kubepods/besteffort/pod<uuid>/<container_id>
		parts := strings.SplitN(line, ":", 3)
		if len(parts) < 3 {
			continue
		}

		cgroupPathPart := parts[2]
		if cgroupPathPart == "" || cgroupPathPart == "/" {
			continue
		}

		// Try to extract container ID from the cgroup path
		containerID := extractContainerID(cgroupPathPart)
		if containerID != "" {
			return containerID, nil
		}
	}

	if err := scanner.Err(); err != nil {
		return "", fmt.Errorf("failed to read %s: %w", cgroupPath, err)
	}

	return "", fmt.Errorf("could not find container ID in %s", cgroupPath)
}

// extractContainerID extracts the container ID from a cgroup path.
// Handles formats like:
//   - /kubepods/besteffort/pod<uuid>/<container_id>
//   - /kubepods.slice/kubepods-besteffort.slice/kubepods-besteffort-pod<uuid>.slice/cri-containerd-<container_id>.scope
func extractContainerID(cgroupPath string) string {
	// Get the last component of the path
	lastComponent := filepath.Base(cgroupPath)

	// Handle cri-containerd scope format: cri-containerd-<container_id>.scope
	if strings.HasPrefix(lastComponent, "cri-containerd-") && strings.HasSuffix(lastComponent, ".scope") {
		// Remove "cri-containerd-" prefix and ".scope" suffix
		id := strings.TrimPrefix(lastComponent, "cri-containerd-")
		id = strings.TrimSuffix(id, ".scope")
		if isValidContainerID(id) {
			return id
		}
	}

	// Handle docker format: docker-<container_id>.scope
	if strings.HasPrefix(lastComponent, "docker-") && strings.HasSuffix(lastComponent, ".scope") {
		id := strings.TrimPrefix(lastComponent, "docker-")
		id = strings.TrimSuffix(id, ".scope")
		if isValidContainerID(id) {
			return id
		}
	}

	// Handle plain container ID format (last path component is the container ID)
	// Example: /kubepods/besteffort/pod<uuid>/<container_id>
	if isValidContainerID(lastComponent) {
		return lastComponent
	}

	return ""
}

// isValidContainerID checks if a string looks like a valid container ID.
// Container IDs are typically 64 hex characters.
func isValidContainerID(id string) bool {
	if len(id) != 64 {
		return false
	}
	for _, c := range id {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return true
}

// getNsPid reads /proc/<pid>/status and extracts the NSpid (PID in container namespace).
// The NSpid line contains space-separated PIDs for each namespace level.
// Example: "NSpid:  12345   1" where 12345 is root ns PID and 1 is container ns PID.
func getNsPid(pid string) (string, error) {
	statusPath := filepath.Join("/proc", pid, "status")
	file, err := os.Open(statusPath)
	if err != nil {
		return "", fmt.Errorf("failed to open %s: %w", statusPath, err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "NSpid:") {
			// Remove "NSpid:" prefix and split by whitespace
			nspidPart := strings.TrimPrefix(line, "NSpid:")
			pids := strings.Fields(nspidPart)
			if len(pids) == 0 {
				return "", fmt.Errorf("NSpid line is empty in %s", statusPath)
			}
			// Return the last PID (innermost namespace)
			return pids[len(pids)-1], nil
		}
	}

	if err := scanner.Err(); err != nil {
		return "", fmt.Errorf("failed to read %s: %w", statusPath, err)
	}

	return "", fmt.Errorf("NSpid not found in %s", statusPath)
}

// execClearRefs runs clear_refs inside the container via crictl exec.
func execClearRefs(containerID, clearRefsBin, nspid string) error {
	// Build the crictl exec command
	cmd := exec.Command("crictl", "exec", containerID, clearRefsBin, nspid)

	// Capture combined output for error reporting
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("crictl exec failed: %w\nOutput: %s", err, string(output))
	}

	if len(output) > 0 {
		fmt.Printf("crictl exec output: %s\n", string(output))
	}

	return nil
}
