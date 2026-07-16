package hostmem

import (
	"os"
	"path/filepath"
	"testing"
)

// fixture builds a fake filesystem root so the fallback chain can be exercised
// without root, containers, or the host's actual memory state.
func fixture(t *testing.T, files map[string]string) Source {
	t.Helper()
	root := t.TempDir()
	for path, content := range files {
		full := filepath.Join(root, path)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return Source{Root: root}
}

const mib = 1024 * 1024

func TestCgroupV2LeafLimitWins(t *testing.T) {
	s := fixture(t, map[string]string{
		"/proc/self/cgroup":                     "0::/mygroup\n",
		"/sys/fs/cgroup/memory.max":             "max\n",
		"/sys/fs/cgroup/memory.current":         "0\n",
		"/sys/fs/cgroup/mygroup/memory.max":     "2097152000\n", // 2000 MiB
		"/sys/fs/cgroup/mygroup/memory.current": "1048576000\n", // 1000 MiB
		"/proc/meminfo":                         "MemAvailable:   99999999 kB\n",
	})
	got, err := s.Available()
	if err != nil {
		t.Fatal(err)
	}
	if want := uint64(1000 * mib); got != want {
		t.Errorf("headroom = %d, want %d", got, want)
	}
}

// A container that caps a parent slice and leaves the leaf unlimited is the
// normal case, and the one a leaf-only read gets catastrophically wrong: it
// would report the host's free memory and admit work that OOM-kills the pod.
func TestCgroupV2ParentLimitBinds(t *testing.T) {
	s := fixture(t, map[string]string{
		"/proc/self/cgroup":                         "0::/parent/leaf\n",
		"/sys/fs/cgroup/memory.max":                 "max\n",
		"/sys/fs/cgroup/memory.current":             "0\n",
		"/sys/fs/cgroup/parent/memory.max":          "524288000\n", // 500 MiB
		"/sys/fs/cgroup/parent/memory.current":      "314572800\n", // 300 MiB
		"/sys/fs/cgroup/parent/leaf/memory.max":     "max\n",
		"/sys/fs/cgroup/parent/leaf/memory.current": "104857600\n",
		"/proc/meminfo":                             "MemAvailable:   99999999 kB\n",
	})
	got, err := s.Available()
	if err != nil {
		t.Fatal(err)
	}
	if want := uint64(200 * mib); got != want {
		t.Errorf("parent cap must bind: headroom = %d, want %d", got, want)
	}
}

// When both levels cap, the tighter one is the one that will actually kill us.
func TestCgroupV2TightestLimitWins(t *testing.T) {
	s := fixture(t, map[string]string{
		"/proc/self/cgroup":                         "0::/parent/leaf\n",
		"/sys/fs/cgroup/memory.max":                 "max\n",
		"/sys/fs/cgroup/memory.current":             "0\n",
		"/sys/fs/cgroup/parent/memory.max":          "1048576000\n", // 1000 MiB
		"/sys/fs/cgroup/parent/memory.current":      "524288000\n",  // → 500 MiB free
		"/sys/fs/cgroup/parent/leaf/memory.max":     "419430400\n",  // 400 MiB
		"/sys/fs/cgroup/parent/leaf/memory.current": "314572800\n",  // → 100 MiB free
		"/proc/meminfo":                             "MemAvailable:   99999999 kB\n",
	})
	got, err := s.Available()
	if err != nil {
		t.Fatal(err)
	}
	if want := uint64(100 * mib); got != want {
		t.Errorf("tightest cap must win: headroom = %d, want %d", got, want)
	}
}

// Usage can exceed max transiently while the kernel reclaims; that is zero
// headroom, not an underflowed enormous number that would admit everything.
func TestCgroupV2OverLimitDoesNotUnderflow(t *testing.T) {
	s := fixture(t, map[string]string{
		"/proc/self/cgroup":               "0::/g\n",
		"/sys/fs/cgroup/memory.max":       "max\n",
		"/sys/fs/cgroup/memory.current":   "0\n",
		"/sys/fs/cgroup/g/memory.max":     "1000\n",
		"/sys/fs/cgroup/g/memory.current": "5000\n",
		"/proc/meminfo":                   "MemAvailable:   99999999 kB\n",
	})
	got, err := s.Available()
	if err != nil {
		t.Fatal(err)
	}
	if got != 0 {
		t.Errorf("over-limit headroom = %d, want 0", got)
	}
}

// This host: cgroup v2 mounted but unlimited all the way up. meminfo is then
// the only real answer, and the cgroup read must not shadow it.
func TestFallsBackToMemInfoWhenCgroupUnlimited(t *testing.T) {
	s := fixture(t, map[string]string{
		"/proc/self/cgroup":                                      "0::/user.slice/session.scope\n",
		"/sys/fs/cgroup/memory.max":                              "max\n",
		"/sys/fs/cgroup/memory.current":                          "100\n",
		"/sys/fs/cgroup/user.slice/memory.max":                   "max\n",
		"/sys/fs/cgroup/user.slice/memory.current":               "100\n",
		"/sys/fs/cgroup/user.slice/session.scope/memory.max":     "max\n",
		"/sys/fs/cgroup/user.slice/session.scope/memory.current": "100\n",
		"/proc/meminfo":                                          "MemTotal:  7553700 kB\nMemAvailable:   4477304 kB\n",
	})
	got, err := s.Available()
	if err != nil {
		t.Fatal(err)
	}
	if want := uint64(4477304) * 1024; got != want {
		t.Errorf("meminfo fallback = %d, want %d", got, want)
	}
}

func TestCgroupV1Limit(t *testing.T) {
	s := fixture(t, map[string]string{
		"/sys/fs/cgroup/memory/memory.limit_in_bytes": "524288000\n", // 500 MiB
		"/sys/fs/cgroup/memory/memory.usage_in_bytes": "104857600\n", // 100 MiB
		"/proc/meminfo": "MemAvailable:   99999999 kB\n",
	})
	got, err := s.Available()
	if err != nil {
		t.Fatal(err)
	}
	if want := uint64(400 * mib); got != want {
		t.Errorf("v1 headroom = %d, want %d", got, want)
	}
}

// v1 reports a huge sentinel rather than "max" when unlimited. Treating it as a
// real cap would report ~8 exabytes free and admit unbounded work.
func TestCgroupV1UnlimitedSentinelIgnored(t *testing.T) {
	s := fixture(t, map[string]string{
		"/sys/fs/cgroup/memory/memory.limit_in_bytes": "9223372036854771712\n",
		"/sys/fs/cgroup/memory/memory.usage_in_bytes": "104857600\n",
		"/proc/meminfo": "MemAvailable:   1024 kB\n",
	})
	got, err := s.Available()
	if err != nil {
		t.Fatal(err)
	}
	if want := uint64(1024 * 1024); got != want {
		t.Errorf("must ignore the v1 sentinel and use meminfo: got %d, want %d", got, want)
	}
}

// Unknown must be an error, never a zero that reads as "no memory left" (which
// would wedge the platform shut) nor a huge number that admits everything.
func TestUnknownWhenNoSource(t *testing.T) {
	s := fixture(t, map[string]string{})
	if _, err := s.Available(); err == nil {
		t.Fatal("want an error when nothing can be read")
	}
}

// The real host must produce a plausible number: this is what catches a fallback
// chain that only ever worked against fixtures.
func TestRealHostReportsSomething(t *testing.T) {
	got, err := Available()
	if err != nil {
		t.Skipf("no memory source on this host: %v", err)
	}
	if got == 0 {
		t.Error("real host reported 0 bytes available")
	}
	t.Logf("available on this host: %d MiB", got/mib)
}
