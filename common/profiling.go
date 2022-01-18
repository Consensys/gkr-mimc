package common

import (
	"fmt"
	"os"
	"path"
	"path/filepath"
	"runtime/trace"
	"testing"

	"github.com/pkg/profile"
)

const GKR_MIMC string = "gkr-mimc"

// Helper to create to a file, and does a few checks
// Ensure it does not create a file from outside the repo
// The path should be specified assuming it is relative to the root of the project
func GetPath(p string) (string, error) {
	base, _ := os.Getwd()

	// Only keeps the part of the base, that leads to the project root
loop:
	for {
		switch path.Base(base) {
		case ".":
			return "", fmt.Errorf("the current directory `%v` is not included in `%v`. try running from another place", GKR_MIMC, base)
		case GKR_MIMC:
			// We stop truncating, we have the right absolute path
			break loop
		default:
			// Truncate the base path : haven't found a better way than this
			base = path.Clean(base + "/..")
		}
	}

	// Get dir where we want to write
	dir, file := filepath.Split(p)
	dir = filepath.Join(base, dir)

	// Ensure the folder was created prior running the test
	if err := os.MkdirAll(dir, os.ModePerm); err != nil {
		return "", err
	}

	// The create the file
	p = filepath.Join(dir, file)
	return p, nil
}

// ProfileTrace run the benchmark function with optionally, benchmarking and tracing
func ProfileTrace(b *testing.B, profiled, traced bool, fn func()) {
	var f *os.File
	var pprof interface{ Stop() }

	if traced {
		_path, err := GetPath(fmt.Sprintf("profiling/%v/trace.out", b.Name()))
		if err != nil {
			panic(err)
		}

		f, err = os.Create(_path)
		if err != nil {
			panic(err)
		}

		err = trace.Start(f)
		if err != nil {
			panic(err)
		}

		defer trace.Stop()
	}

	if profiled {
		_path, err := GetPath(fmt.Sprintf("profiling/%v/profile.pprof", b.Name()))
		if err != nil {
			panic(err)
		}

		pprof = profile.Start(
			profile.ProfilePath(_path),
			profile.Quiet,
		)
		defer pprof.Stop()
	}

	b.StartTimer()
	defer b.StopTimer()

	fn()
}
