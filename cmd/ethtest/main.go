// SPDX-License-Identifier: Apache-2.0

// Command ethtest runs the Ethereum state-test fixtures against Burrow's EVM.
//
//	go run ./cmd/ethtest            run everything and print a summary
//	go run ./cmd/ethtest -write     also rewrite the scoreboard and pass list
//	go run ./cmd/ethtest -check     CI mode: fail on any regression or drift
//	go run ./cmd/ethtest -v ID      explain one case
//
// The exit code is the result: 0 only when nothing failed that must not.
package main

import (
	"bufio"
	"bytes"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/hyperledger/burrow/execution/ethtest"
	"github.com/hyperledger/burrow/execution/ethtest/fixture"
)

type paths struct {
	lock, scoreboard, passing string
}

func main() {
	if os.Getenv(workerEnv) == "1" {
		os.Exit(worker(os.Args[1:], os.Stdout, os.Stderr))
	}
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("ethtest", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fixtures := fs.String("fixtures", "tests/ethereum/fixtures", "unpacked fixture release")
	runFilter := fs.String("run", "", "only run cases whose ID matches this regular expression")
	var p paths
	fs.StringVar(&p.lock, "lock", "tests/ethereum/fixtures.lock", "fixture lock file")
	fs.StringVar(&p.scoreboard, "scoreboard", "tests/ethereum/scoreboard.md", "generated scoreboard")
	fs.StringVar(&p.passing, "passing", "tests/ethereum/passing.txt", "IDs of passing cases (the ratchet)")
	write := fs.Bool("write", false, "rewrite the scoreboard and the passing list")
	check := fs.Bool("check", false, "fail on regressions, errors, count or scoreboard drift")
	explain := fs.String("v", "", "explain one case by ID")
	resultsFile := fs.String("results", "", "write one line per case (ID, status, reason; tab-separated) to this file")
	timeout := fs.Duration("timeout", 20*time.Second, "per-case time limit; longer cases fail with reason timeout")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *runFilter != "" && (*write || *check) {
		fmt.Fprintln(stderr, "-run cannot be combined with -write or -check")
		return 2
	}
	if _, err := os.Stat(*fixtures); err != nil {
		fmt.Fprintf(stderr, "fixtures not found at %s: run tests/scripts/fetch_eth_fixtures.sh\n", *fixtures)
		return 1
	}
	stateRoot := filepath.Join(*fixtures, "state_tests")
	if *explain != "" {
		return explainCase(stateRoot, *explain, stdout, stderr)
	}

	lock, err := readLock(p.lock)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	var filter *regexp.Regexp
	if *runFilter != "" {
		if filter, err = regexp.Compile(*runFilter); err != nil {
			fmt.Fprintf(stderr, "-run: %v\n", err)
			return 2
		}
	}

	results, err := runAll(stateRoot, filter, *timeout)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	pass, errs := 0, 0
	for _, r := range results {
		switch r.Status {
		case ethtest.Pass:
			pass++
		case ethtest.Error:
			errs++
			fmt.Fprintf(stderr, "error: %s: %s\n", r.ID, r.Reason)
		}
	}
	fmt.Fprintf(stdout, "ethtest %s: %d/%d pass, %d errors\n", lock["release"], pass, len(results), errs)

	if *resultsFile != "" {
		var b strings.Builder
		for _, r := range results {
			fmt.Fprintf(&b, "%s\t%s\t%s\n", r.ID, r.Status, r.Reason)
		}
		if err := os.WriteFile(*resultsFile, []byte(b.String()), 0o644); err != nil {
			fmt.Fprintln(stderr, err)
			return 1
		}
	}

	scoreboard := ethtest.Scoreboard(results, lock["release"], lock["sha256"])
	if *write {
		if err := os.WriteFile(p.scoreboard, scoreboard, 0o644); err != nil {
			fmt.Fprintln(stderr, err)
			return 1
		}
		if err := os.WriteFile(p.passing, ethtest.PassingList(results), 0o644); err != nil {
			fmt.Fprintln(stderr, err)
			return 1
		}
	}

	failed := errs > 0
	if *check {
		failed = checkAll(*fixtures, p, lock, results, scoreboard, stdout, stderr) || failed
	}
	if failed {
		return 1
	}
	return 0
}

// checkAll runs every -check condition and reports each failure on its own line.
func checkAll(fixtures string, p paths, lock map[string]string, results []ethtest.Result, scoreboard []byte, stdout, stderr io.Writer) bool {
	failed := false
	fail := func(format string, args ...interface{}) {
		failed = true
		fmt.Fprintf(stderr, "check failed: "+format+"\n", args...)
	}

	genesis, err := ethtest.CheckGenesisRoots(fixtures)
	switch {
	case err != nil:
		fail("genesis root self-check: %v", err)
	case !genesis.OK():
		fail("genesis root self-check: checked %d, mismatched %d", genesis.Checked, genesis.Mismatched)
		for _, m := range genesis.Mismatches {
			fmt.Fprintln(stderr, "  "+m)
		}
	default:
		fmt.Fprintf(stdout, "genesis root self-check: %d/%d match\n", genesis.Matched, genesis.Checked)
	}

	if want := lock["state_cases"]; want != strconv.Itoa(len(results)) {
		fail("found %d state cases, %s says state_cases=%s", len(results), p.lock, want)
	}

	prev, err := readLines(p.passing)
	if err != nil {
		fail("%v", err)
	}
	for _, id := range ethtest.Regressions(prev, results) {
		fail("regression: %s no longer passes", id)
	}

	committed, err := os.ReadFile(p.scoreboard)
	if err != nil {
		fail("%v", err)
	} else if !bytes.Equal(committed, scoreboard) {
		fail("%s differs from this run; regenerate it with -write", p.scoreboard)
	}
	return failed
}

func runAll(stateRoot string, filter *regexp.Regexp, timeout time.Duration) ([]ethtest.Result, error) {
	filterSource := ""
	if filter != nil {
		filterSource = filter.String()
	}
	self, err := os.Executable()
	if err != nil {
		return nil, fmt.Errorf("locating ethtest binary for workers: %w", err)
	}
	var files []string
	if err := fixture.Walk(filepath.Dir(stateRoot), filepath.Base(stateRoot), func(f string) error {
		files = append(files, f)
		return nil
	}); err != nil {
		return nil, err
	}

	type fileResult struct {
		results []ethtest.Result
		err     error
	}
	out := make([]fileResult, len(files))
	jobs := make(chan int)
	var wg sync.WaitGroup
	for w := 0; w < runtime.GOMAXPROCS(0); w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range jobs {
				rs, err := runFileIsolated(self, stateRoot, files[i], filterSource, timeout)
				out[i] = fileResult{rs, err}
			}
		}()
	}
	for i := range files {
		jobs <- i
	}
	close(jobs)
	wg.Wait()

	var results []ethtest.Result
	for _, fr := range out {
		if fr.err != nil {
			return nil, fr.err
		}
		for _, r := range fr.results {
			if filter == nil || filter.MatchString(r.ID) {
				results = append(results, r)
			}
		}
	}
	sort.Slice(results, func(a, b int) bool { return results[a].ID < results[b].ID })
	return results, nil
}

func explainCase(stateRoot, id string, stdout, stderr io.Writer) int {
	path, name, fork, idx, err := splitID(id)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}
	tests, err := fixture.LoadStateTests(filepath.Join(stateRoot, filepath.FromSlash(path)))
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	t, ok := tests[name]
	if !ok {
		fmt.Fprintf(stderr, "no test %q in %s\n", name, path)
		return 1
	}
	fmt.Fprint(stdout, ethtest.Explain(id, t, fork, idx))
	return 0
}

// splitID splits <path>::<test name>::<fork>::<index>. Test names contain "::".
func splitID(id string) (path, name, fork string, idx int, err error) {
	parts := strings.Split(id, "::")
	if len(parts) < 4 {
		return "", "", "", 0, fmt.Errorf("malformed case ID %q", id)
	}
	idx, err = strconv.Atoi(parts[len(parts)-1])
	if err != nil {
		return "", "", "", 0, fmt.Errorf("malformed case ID %q: %w", id, err)
	}
	path = parts[0]
	name = strings.Join(parts[1:len(parts)-2], "::")
	fork = parts[len(parts)-2]
	return path, name, fork, idx, nil
}

func readLock(path string) (map[string]string, error) {
	lines, err := readLines(path)
	if err != nil {
		return nil, err
	}
	lock := make(map[string]string)
	for _, l := range lines {
		if k, v, ok := cut(l, "="); ok {
			lock[k] = v
		}
	}
	for _, k := range []string{"release", "sha256", "state_cases"} {
		if lock[k] == "" {
			return nil, fmt.Errorf("%s: missing %s", path, k)
		}
	}
	return lock, nil
}

func cut(s, sep string) (before, after string, found bool) {
	if i := strings.Index(s, sep); i >= 0 {
		return s[:i], s[i+len(sep):], true
	}
	return s, "", false
}

func readLines(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", path, err)
	}
	defer f.Close()
	var lines []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if l := strings.TrimSpace(sc.Text()); l != "" {
			lines = append(lines, l)
		}
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("reading %s: %w", path, err)
	}
	return lines, nil
}
