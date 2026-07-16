// Package hostmem reports how much memory the process may still use.
//
// It exists because "how much RAM is left" has three different answers on Linux
// and only one of them is right for a given deployment. A container with a
// memory limit will be OOM-killed at that limit no matter how much the host has
// free, so reading /proc/meminfo inside one over-reports wildly. Conversely a
// process with no cgroup limit is bounded only by the host, where a cgroup read
// would find "max" and report nothing useful.
//
// The order below is therefore deliberate: the tightest limit that actually
// applies to this process wins.
//
//  1. cgroup v2 — walk from the process's own cgroup up to the root and take the
//     smallest numeric memory.max. Limits are inherited, so an ancestor's cap
//     binds even when the leaf says "max".
//  2. cgroup v1 — memory.limit_in_bytes, which reports a huge sentinel rather
//     than "max" when unlimited.
//  3. /proc/meminfo MemAvailable — the kernel's own estimate of what can be
//     allocated without swapping, which is a better answer than MemFree because
//     it accounts for reclaimable page cache.
package hostmem

import (
	"bufio"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// ErrUnknown is returned when no source could report available memory. Callers
// must decide what to do with "unknown" rather than being handed a zero that
// looks like "no memory left".
var ErrUnknown = errors.New("hostmem: cannot determine available memory")

// v1Unlimited is the sentinel cgroup v1 uses for "no limit". It is
// PAGE_COUNTER_MAX pages, and comparing against it is how the kernel's own
// tooling detects an unset limit; anything at or above it is not a real cap.
const v1Unlimited uint64 = 9223372036854771712

// Source reads memory facts under a filesystem root. The root is a field so the
// fallback chain can be tested against fixture trees; production uses Default.
type Source struct{ Root string }

// Default reads the real filesystem.
var Default = Source{}

// Available returns the bytes this process can still allocate, using the
// tightest limit that applies to it.
func Available() (uint64, error) { return Default.Available() }

func (s Source) path(p string) string { return filepath.Join(s.Root, p) }

// Available reports remaining bytes under the binding limit.
func (s Source) Available() (uint64, error) {
	if avail, ok := s.cgroupV2Available(); ok {
		return avail, nil
	}
	if avail, ok := s.cgroupV1Available(); ok {
		return avail, nil
	}
	if avail, ok := s.procMemAvailable(); ok {
		return avail, nil
	}
	return 0, ErrUnknown
}

// cgroupV2Available finds the binding memory.max in this process's cgroup chain
// and reports the headroom under it.
//
// The walk matters: containers commonly leave the leaf cgroup unlimited and cap
// a parent slice. Stopping at the leaf would read "max" and conclude, wrongly,
// that the process is unconstrained.
func (s Source) cgroupV2Available() (uint64, bool) {
	rel, ok := s.selfCgroupV2()
	if !ok {
		return 0, false
	}
	var (
		best   uint64
		found  bool
		curDir = filepath.Join(s.path("/sys/fs/cgroup"), filepath.Clean("/"+rel))
		root   = s.path("/sys/fs/cgroup")
	)
	for {
		maxV, okMax := readUintFile(filepath.Join(curDir, "memory.max"))
		curV, okCur := readUintFile(filepath.Join(curDir, "memory.current"))
		if okMax && okCur {
			// Headroom under this level's cap. Never underflow: usage can exceed
			// max transiently while the kernel reclaims.
			var headroom uint64
			if maxV > curV {
				headroom = maxV - curV
			}
			if !found || headroom < best {
				best, found = headroom, true
			}
		}
		if curDir == root || !strings.HasPrefix(curDir, root) {
			break
		}
		parent := filepath.Dir(curDir)
		if parent == curDir {
			break
		}
		curDir = parent
	}
	return best, found
}

// selfCgroupV2 returns the process's unified-hierarchy cgroup path. The v2 line
// in /proc/self/cgroup is the one with an empty controller field: "0::/path".
func (s Source) selfCgroupV2() (string, bool) {
	f, err := os.Open(s.path("/proc/self/cgroup"))
	if err != nil {
		return "", false
	}
	defer func() { _ = f.Close() }()

	sc := bufio.NewScanner(f)
	for sc.Scan() {
		parts := strings.SplitN(sc.Text(), ":", 3)
		if len(parts) == 3 && parts[0] == "0" && parts[1] == "" {
			return parts[2], true
		}
	}
	return "", false
}

// cgroupV1Available reports headroom under the v1 memory controller's limit.
func (s Source) cgroupV1Available() (uint64, bool) {
	base := s.path("/sys/fs/cgroup/memory")
	limit, okL := readUintFile(filepath.Join(base, "memory.limit_in_bytes"))
	usage, okU := readUintFile(filepath.Join(base, "memory.usage_in_bytes"))
	if !okL || !okU || limit >= v1Unlimited {
		return 0, false
	}
	if limit <= usage {
		return 0, true
	}
	return limit - usage, true
}

// procMemAvailable reads MemAvailable (kB) from /proc/meminfo.
func (s Source) procMemAvailable() (uint64, bool) {
	f, err := os.Open(s.path("/proc/meminfo"))
	if err != nil {
		return 0, false
	}
	defer func() { _ = f.Close() }()

	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		if !strings.HasPrefix(line, "MemAvailable:") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			return 0, false
		}
		kb, err := strconv.ParseUint(fields[1], 10, 64)
		if err != nil {
			return 0, false
		}
		return kb * 1024, true
	}
	return 0, false
}

// readUintFile reads a file holding a single integer. "max" (cgroup v2's
// unlimited) is reported as absent rather than as a huge number, so a caller
// comparing limits never mistakes "no cap" for "an enormous cap".
func readUintFile(path string) (uint64, bool) {
	b, err := os.ReadFile(path)
	if err != nil {
		return 0, false
	}
	s := strings.TrimSpace(string(b))
	if s == "max" || s == "" {
		return 0, false
	}
	v, err := strconv.ParseUint(s, 10, 64)
	if err != nil {
		return 0, false
	}
	return v, true
}
