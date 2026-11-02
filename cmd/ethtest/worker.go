// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"os"
	"os/exec"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/hyperledger/burrow/execution/ethtest"
)

// Burrow's EVM cannot be interrupted, and some cases never finish under its
// gas schedule. Each fixture file therefore runs in a child process (this same
// binary with workerEnv set) that the parent kills when a case overruns.
const workerEnv = "ETHTEST_WORKER"

// workerMemEnv carries the worker's heap ceiling in bytes.
const workerMemEnv = "ETHTEST_WORKER_MEM"

// watchMemory stops the worker when its heap passes limit bytes, so a case
// that makes Burrow allocate without bound cannot exhaust the machine. The
// parent records it as a crash.
func watchMemory(limit uint64, stderr io.Writer) {
	var m runtime.MemStats
	for range time.Tick(20 * time.Millisecond) {
		runtime.ReadMemStats(&m)
		if m.HeapAlloc > limit {
			fmt.Fprintln(stderr, "fatal error: worker memory limit exceeded")
			os.Exit(3)
		}
	}
}

// worker runs the cases of one file after the given ID, in ID order, and
// reports each on stdout as "start\tID", then "exec\tID" as Burrow's EVM is
// entered, then "result\tID\tstatus\treason".
// Args: stateRoot path afterID filter; afterID and filter may be empty.
func worker(args []string, stdout, stderr io.Writer) int {
	if len(args) != 4 {
		fmt.Fprintln(stderr, "worker: want stateRoot path afterID filter")
		return 2
	}
	after := args[2]
	var filter *regexp.Regexp
	if args[3] != "" {
		var err error
		if filter, err = regexp.Compile(args[3]); err != nil {
			fmt.Fprintln(stderr, err)
			return 2
		}
	}
	if limit, err := strconv.ParseUint(os.Getenv(workerMemEnv), 10, 64); err == nil && limit > 0 {
		go watchMemory(limit, stderr)
	}
	cases, err := ethtest.Cases(args[0], args[1])
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 3
	}
	w := bufio.NewWriter(stdout)
	for _, c := range cases {
		if (after != "" && c.ID <= after) || (filter != nil && !filter.MatchString(c.ID)) {
			continue
		}
		fmt.Fprintf(w, "start\t%s\n", c.ID)
		w.Flush()
		id := c.ID
		r := c.RunWith(func() {
			fmt.Fprintf(w, "exec\t%s\n", id)
			w.Flush()
		})
		fmt.Fprintf(w, "result\t%s\t%s\t%s\n", r.ID, r.Status, oneLine(r.Reason))
		w.Flush()
	}
	return 0
}

func oneLine(s string) string {
	return strings.NewReplacer("\n", " ", "\r", " ", "\t", " ").Replace(s)
}

func parseStatus(s string) ethtest.Status {
	switch s {
	case "pass":
		return ethtest.Pass
	case "fail":
		return ethtest.Fail
	default:
		return ethtest.Error
	}
}

// runFileIsolated runs one fixture file through worker processes. Inside
// Burrow's EVM, a case that runs longer than timeout is "fail: timeout" and a
// worker that dies is "fail: crash: ...". Outside it, either is a harness
// error. Either way the next worker resumes after that case.
func runFileIsolated(self, stateRoot, path, filter string, timeout time.Duration, memLimit uint64) ([]ethtest.Result, error) {
	var results []ethtest.Result
	after := ""
	for {
		cmd := exec.Command(self, stateRoot, path, after, filter)
		cmd.Env = append(os.Environ(), workerEnv+"=1", fmt.Sprintf("%s=%d", workerMemEnv, memLimit))
		var stderr bytes.Buffer
		cmd.Stderr = &stderr
		out, err := cmd.StdoutPipe()
		if err != nil {
			return nil, fmt.Errorf("worker for %s: %w", path, err)
		}
		if err := cmd.Start(); err != nil {
			return nil, fmt.Errorf("starting worker for %s: %w", path, err)
		}

		lines := make(chan string)
		go func() {
			sc := bufio.NewScanner(out)
			sc.Buffer(make([]byte, 1<<20), 1<<20)
			for sc.Scan() {
				lines <- sc.Text()
			}
			close(lines)
		}()

		current, inBurrow := "", false
		var timer <-chan time.Time
		resumed := false
	read:
		for {
			select {
			case line, ok := <-lines:
				if !ok {
					break read
				}
				fields := strings.SplitN(line, "\t", 4)
				switch {
				case fields[0] == "start" && len(fields) == 2:
					current, inBurrow = fields[1], false
					timer = time.After(timeout)
				case fields[0] == "exec" && len(fields) == 2 && fields[1] == current:
					inBurrow = true
				case fields[0] == "result" && len(fields) == 4:
					results = append(results, ethtest.Result{
						ID: fields[1], Fork: forkOf(fields[1]), Status: parseStatus(fields[2]), Reason: fields[3],
					})
					current, timer = "", nil
				default:
					_ = cmd.Process.Kill()
					_ = cmd.Wait()
					return nil, fmt.Errorf("worker for %s: unexpected output %q", path, line)
				}
			case <-timer:
				_ = cmd.Process.Kill()
				for range lines {
				}
				_ = cmd.Wait()
				if inBurrow {
					results = append(results, ethtest.Result{ID: current, Fork: forkOf(current), Status: ethtest.Fail, Reason: "timeout"})
				} else {
					results = append(results, ethtest.Result{ID: current, Fork: forkOf(current), Status: ethtest.Error, Reason: "harness timeout"})
				}
				after, resumed = current, true
				break read
			}
		}
		if resumed {
			continue
		}
		waitErr := cmd.Wait()
		if current != "" {
			why := oneLine(crashLine(stderr.String()))
			if inBurrow {
				results = append(results, ethtest.Result{ID: current, Fork: forkOf(current), Status: ethtest.Fail, Reason: "crash: " + why})
			} else {
				results = append(results, ethtest.Result{ID: current, Fork: forkOf(current), Status: ethtest.Error, Reason: "worker crashed: " + why})
			}
			after = current
			continue
		}
		if waitErr != nil {
			return nil, fmt.Errorf("worker for %s: %w: %s", path, waitErr, strings.TrimSpace(stderr.String()))
		}
		return results, nil
	}
}

func forkOf(id string) string {
	_, _, fork, _, err := splitID(id)
	if err != nil {
		return ""
	}
	return fork
}

// crashLine picks the Go runtime's "fatal error:" or "panic:" line from a dead
// worker's stderr, falling back to its last line.
func crashLine(stderr string) string {
	lines := strings.Split(strings.TrimSpace(stderr), "\n")
	for _, l := range lines {
		if strings.HasPrefix(l, "fatal error:") || strings.HasPrefix(l, "panic:") {
			return l
		}
	}
	return lines[len(lines)-1]
}
