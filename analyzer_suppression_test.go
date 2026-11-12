// (c) Copyright gosec's authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package gosec_test

import (
	"fmt"
	"io"
	"log"
	"strings"
	"testing"

	"github.com/securego/gosec/v2"
	"github.com/securego/gosec/v2/analyzers"
	"github.com/securego/gosec/v2/issue"
	"github.com/securego/gosec/v2/rules"
	"github.com/securego/gosec/v2/testutils"
)

// scanOptions customizes the analyzer used by scanSource.
type scanOptions struct {
	config            gosec.Config
	excludeGenerated  bool
	trackSuppressions bool
	concurrency       int
	ruleIDs           []string
	analyzerIDs       []string
}

// scanSource writes src into a temporary package, scans it with the G401
// rule (plus any extra rules/analyzers requested) and reports the results.
func scanSource(t *testing.T, src string, opts scanOptions) ([]*issue.Issue, *gosec.Metrics, map[string][]gosec.Error) {
	t.Helper()
	return scanFiles(t, map[string]string{"main.go": src}, opts)
}

// scanFiles writes the given files into a temporary package and scans it.
func scanFiles(t *testing.T, files map[string]string, opts scanOptions) ([]*issue.Issue, *gosec.Metrics, map[string][]gosec.Error) {
	t.Helper()

	conf := opts.config
	if conf == nil {
		conf = gosec.NewConfig()
	}
	concurrency := opts.concurrency
	if concurrency < 1 {
		concurrency = 1
	}
	analyzer := gosec.NewAnalyzer(conf, false, opts.excludeGenerated, opts.trackSuppressions,
		concurrency, log.New(io.Discard, "", 0))

	ruleIDs := opts.ruleIDs
	if len(ruleIDs) == 0 {
		ruleIDs = []string{"G401"}
	}
	analyzer.LoadRules(rules.Generate(false, rules.NewRuleFilter(false, ruleIDs...)).RulesInfo())
	if len(opts.analyzerIDs) > 0 {
		analyzer.LoadAnalyzers(analyzers.Generate(false, analyzers.NewAnalyzerFilter(false, opts.analyzerIDs...)).AnalyzersInfo())
	}

	pkg := testutils.NewTestPackage()
	defer pkg.Close()
	for name, content := range files {
		pkg.AddFile(name, content)
	}
	if err := pkg.Build(); err != nil {
		t.Fatalf("building test package: %v", err)
	}
	if err := analyzer.Process(nil, pkg.Path); err != nil {
		t.Fatalf("processing test package: %v", err)
	}
	return analyzer.Report()
}

// md5Package returns a source file whose md5 call carries the given comment.
func md5Package(directive string) string {
	return fmt.Sprintf(`package main

import "crypto/md5"

func f() {
	h := md5.New() %s
	_ = h
}

func main() {}
`, directive)
}

// errCount totals the errors across all files.
func errCount(errs map[string][]gosec.Error) int {
	n := 0
	for _, e := range errs {
		n += len(e)
	}
	return n
}

// TestNoSecRuleIDParsing checks that rule IDs in nosec directives are parsed
// strictly: identifiers such as G4012 or fooG401bar must never suppress a
// finding, and a directive without any valid rule ID is reported as invalid
// instead of silently suppressing everything.
func TestNoSecRuleIDParsing(t *testing.T) {
	t.Parallel()

	for _, tt := range []struct {
		name          string
		directive     string
		wantSuppressed bool
		wantErrors    int
	}{
		{name: "valid single rule", directive: "//#nosec G401", wantSuppressed: true},
		{name: "valid rule list", directive: "//#nosec G301 G401", wantSuppressed: true},
		{name: "valid comma separated list", directive: "//#nosec G301,G401", wantSuppressed: true},
		{name: "valid gosec:disable", directive: "//gosec:disable G401", wantSuppressed: true},
		{name: "valid gosec:disable with tab", directive: "//gosec:disable\tG401", wantSuppressed: true},
		{name: "overlong rule ID", directive: "//#nosec G4012", wantErrors: 1},
		{name: "short rule ID", directive: "//#nosec G40", wantErrors: 1},
		{name: "rule ID embedded in token", directive: "//#nosec fooG401bar", wantErrors: 1},
		{name: "garbage directive", directive: "//#nosec XYZ", wantErrors: 1},
		{name: "overlong rule ID in disable", directive: "//gosec:disable G4012", wantErrors: 1},
	} {
		t.Run(tt.name, func(t *testing.T) {
			issues, metrics, errs := scanSource(t, md5Package(tt.directive), scanOptions{})

			suppressed := len(issues) == 0
			if suppressed != tt.wantSuppressed {
				t.Fatalf("directive %q: suppressed=%v, want %v (issues: %v)", tt.directive, suppressed, tt.wantSuppressed, issues)
			}
			if got := errCount(errs); got != tt.wantErrors {
				t.Fatalf("directive %q: got %d errors, want %d: %v", tt.directive, got, tt.wantErrors, errs)
			}
			if tt.wantSuppressed && metrics.NumNosec != 1 {
				t.Fatalf("directive %q: got %d nosec directives, want 1", tt.directive, metrics.NumNosec)
			}
			if tt.wantErrors > 0 && metrics.NumNosec != 0 {
				t.Fatalf("directive %q: invalid directive must not be counted as nosec, got %d", tt.directive, metrics.NumNosec)
			}
		})
	}
}

// TestNoSecNestedFunctionScope checks that a nosec directive applies to the
// syntactic range it annotates: a directive inside a nested function literal
// suppresses only the findings of that literal, while a directive on the
// enclosing function covers everything inside it.
func TestNoSecNestedFunctionScope(t *testing.T) {
	t.Parallel()

	t.Run("directive inside closure does not leak", func(t *testing.T) {
		issues, metrics, errs := scanSource(t, `package main

import "crypto/md5"

func outer() {
	//#nosec G401 -- only the closure
	func() {
		h := md5.New()
		_ = h
	}()
	h2 := md5.New()
	_ = h2
}

func main() {}
`, scanOptions{trackSuppressions: true})
		if errCount(errs) != 0 {
			t.Fatalf("unexpected errors: %v", errs)
		}
		if len(issues) != 2 {
			t.Fatalf("got %d issues, want 2 (suppressed findings are tracked)", len(issues))
		}
		var suppressed, active int
		for _, iss := range issues {
			if iss.NoSec {
				suppressed++
				if len(iss.Suppressions) == 0 {
					t.Fatalf("suppressed issue at line %s carries no suppression info", iss.Line)
				}
			} else {
				active++
			}
		}
		if suppressed != 1 || active != 1 {
			t.Fatalf("got %d suppressed and %d active findings, want 1 each", suppressed, active)
		}
		if metrics.NumNosec != 1 {
			t.Fatalf("got %d nosec directives, want 1", metrics.NumNosec)
		}
	})

	t.Run("directive on outer function covers nested closures", func(t *testing.T) {
		issues, _, errs := scanSource(t, `package main

import "crypto/md5"

//#nosec G401 -- whole function
func outer() {
	func() {
		h := md5.New()
		_ = h
	}()
	h2 := md5.New()
	_ = h2
}

func main() {}
`, scanOptions{})
		if errCount(errs) != 0 {
			t.Fatalf("unexpected errors: %v", errs)
		}
		if len(issues) != 0 {
			t.Fatalf("got %d issues, want 0: %v", len(issues), issues)
		}
	})
}

// TestNoSecDuplicateRuleIDs checks that repeating a rule ID in a single
// directive does not duplicate the recorded suppression nor the nosec count.
func TestNoSecDuplicateRuleIDs(t *testing.T) {
	t.Parallel()

	issues, metrics, errs := scanSource(t, md5Package("//#nosec G401 G401 -- justified"), scanOptions{trackSuppressions: true})
	if errCount(errs) != 0 {
		t.Fatalf("unexpected errors: %v", errs)
	}
	if len(issues) != 1 {
		t.Fatalf("got %d issues, want 1 (tracked suppression)", len(issues))
	}
	if got := len(issues[0].Suppressions); got != 1 {
		t.Fatalf("got %d suppressions, want 1: %#v", got, issues[0].Suppressions)
	}
	if issues[0].Suppressions[0].Justification != "justified" {
		t.Fatalf("unexpected justification: %q", issues[0].Suppressions[0].Justification)
	}
	if metrics.NumNosec != 1 {
		t.Fatalf("got %d nosec directives, want 1", metrics.NumNosec)
	}
}

// TestNoSecEmptyJustification checks that an empty `--` justification is
// rejected when justifications are required and recorded as empty otherwise.
func TestNoSecEmptyJustification(t *testing.T) {
	t.Parallel()

	t.Run("rejected when justification is required", func(t *testing.T) {
		conf := gosec.NewConfig()
		conf.SetGlobal(gosec.NoSecRequireJustification, "true")
		issues, _, errs := scanSource(t, md5Package("//#nosec G401 --"), scanOptions{config: conf})
		if len(issues) != 1 {
			t.Fatalf("got %d issues, want 1 (directive must not suppress)", len(issues))
		}
		if errCount(errs) != 1 {
			t.Fatalf("got %d errors, want 1: %v", errCount(errs), errs)
		}
	})

	t.Run("recorded empty when justification is optional", func(t *testing.T) {
		issues, _, errs := scanSource(t, md5Package("//#nosec G401 --"), scanOptions{trackSuppressions: true})
		if errCount(errs) != 0 {
			t.Fatalf("unexpected errors: %v", errs)
		}
		if len(issues) != 1 || len(issues[0].Suppressions) != 1 {
			t.Fatalf("got %#v, want a single tracked suppression", issues)
		}
		if issues[0].Suppressions[0].Justification != "" {
			t.Fatalf("unexpected justification: %q", issues[0].Suppressions[0].Justification)
		}
	})
}

// TestNoSecLineDirectiveRange checks that suppressions apply to issues
// reported at //line-adjusted positions: issues are reported where the //line
// directive maps them to, and the nosec directive must still match them.
func TestNoSecLineDirectiveRange(t *testing.T) {
	t.Parallel()

	issues, metrics, errs := scanSource(t, `package main

import "crypto/md5"

//line virtual.go:100
func f() {
	h := md5.New() //#nosec G401
	_ = h
}

func main() {}
`, scanOptions{trackSuppressions: true})
	if errCount(errs) != 0 {
		t.Fatalf("unexpected errors: %v", errs)
	}
	if len(issues) != 1 {
		t.Fatalf("got %d issues, want 1 (tracked suppression)", len(issues))
	}
	iss := issues[0]
	if !strings.HasSuffix(iss.File, "virtual.go") {
		t.Fatalf("issue reported in %q, want the //line-adjusted file virtual.go", iss.File)
	}
	if iss.Line != "101" {
		t.Fatalf("issue reported at line %s, want 101", iss.Line)
	}
	if !iss.NoSec || len(iss.Suppressions) != 1 {
		t.Fatalf("issue at the //line-adjusted position was not suppressed: %#v", iss)
	}
	if metrics.NumNosec != 1 {
		t.Fatalf("got %d nosec directives, want 1", metrics.NumNosec)
	}
}

// TestGeneratedFilesExcluded checks that generated files are excluded
// consistently from both the AST rules and the file metrics.
func TestGeneratedFilesExcluded(t *testing.T) {
	t.Parallel()

	generated := `// Code generated by test. DO NOT EDIT.

package main

import "crypto/md5"

func generated() {
	h := md5.New()
	_ = h
}
`
	handwritten := `package main

import "crypto/md5"

func handwritten() {
	h := md5.New()
	_ = h
}

func main() {}
`
	files := map[string]string{"gen.go": generated, "main.go": handwritten}

	t.Run("generated findings and files are excluded", func(t *testing.T) {
		issues, metrics, errs := scanFiles(t, files, scanOptions{excludeGenerated: true})
		if errCount(errs) != 0 {
			t.Fatalf("unexpected errors: %v", errs)
		}
		if len(issues) != 1 {
			t.Fatalf("got %d issues, want 1 (only the handwritten finding): %v", len(issues), issues)
		}
		if strings.HasSuffix(issues[0].File, "gen.go") {
			t.Fatalf("finding reported in excluded generated file: %v", issues[0].File)
		}
		if metrics.NumFiles != 1 {
			t.Fatalf("got %d scanned files, want 1", metrics.NumFiles)
		}
		if metrics.NumFound != 1 {
			t.Fatalf("got %d findings, want 1", metrics.NumFound)
		}
	})

	t.Run("generated findings are reported when not excluded", func(t *testing.T) {
		issues, metrics, errs := scanFiles(t, files, scanOptions{})
		if errCount(errs) != 0 {
			t.Fatalf("unexpected errors: %v", errs)
		}
		if len(issues) != 2 {
			t.Fatalf("got %d issues, want 2", len(issues))
		}
		if metrics.NumFiles != 2 {
			t.Fatalf("got %d scanned files, want 2", metrics.NumFiles)
		}
	})
}

// TestConcurrentScanDeterministic checks that scanning multiple packages
// concurrently produces the same findings and nosec statistics as repeated
// runs, and that passing the same package path twice does not double-count.
func TestConcurrentScanDeterministic(t *testing.T) {
	t.Parallel()

	const pkgCount = 4
	pkgs := make([]*testutils.TestPackage, 0, pkgCount)
	paths := make([]string, 0, pkgCount)
	for i := 0; i < pkgCount; i++ {
		pkg := testutils.NewTestPackage()
		defer pkg.Close()
		// Half of the packages suppress their finding, the rest do not.
		directive := ""
		if i%2 == 0 {
			directive = "//#nosec G401 -- accepted risk"
		}
		pkg.AddFile("main.go", md5Package(directive))
		if err := pkg.Build(); err != nil {
			t.Fatalf("building test package: %v", err)
		}
		pkgs = append(pkgs, pkg)
		paths = append(paths, pkg.Path)
	}

	scan := func(paths ...string) ([]*issue.Issue, *gosec.Metrics) {
		analyzer := gosec.NewAnalyzer(gosec.NewConfig(), false, false, false, 8, log.New(io.Discard, "", 0))
		analyzer.LoadRules(rules.Generate(false, rules.NewRuleFilter(false, "G401")).RulesInfo())
		if err := analyzer.Process(nil, paths...); err != nil {
			t.Fatalf("processing packages: %v", err)
		}
		issues, metrics, errs := analyzer.Report()
		if errCount(errs) != 0 {
			t.Fatalf("unexpected errors: %v", errs)
		}
		return issues, metrics
	}

	issues1, metrics1 := scan(paths...)
	issues2, metrics2 := scan(paths...)

	if len(issues1) != 2 || len(issues2) != 2 {
		t.Fatalf("got %d and %d findings, want 2 each (unsuppressed packages only)", len(issues1), len(issues2))
	}
	if *metrics1 != *metrics2 {
		t.Fatalf("non-deterministic metrics: first %#v, second %#v", metrics1, metrics2)
	}
	if metrics1.NumNosec != 2 {
		t.Fatalf("got %d nosec directives, want 2", metrics1.NumNosec)
	}
	if metrics1.NumFound != 2 {
		t.Fatalf("got %d findings, want 2", metrics1.NumFound)
	}

	// Scanning the same path twice in one run must not duplicate anything.
	dupIssues, dupMetrics := scan(paths[0], paths[0])
	singleIssues, singleMetrics := scan(paths[0])
	if len(dupIssues) != len(singleIssues) || *dupMetrics != *singleMetrics {
		t.Fatalf("duplicate package paths double-counted: got %d issues %#v, want %d issues %#v",
			len(dupIssues), dupMetrics, len(singleIssues), singleMetrics)
	}
}

// TestSuppressionStatsConsistency checks that the nosec statistics and the
// issue fields stay consistent across the supported reporting modes: a
// suppressed finding is never counted as found, and a reported suppressed
// finding always carries both the nosec flag and its suppression info.
func TestSuppressionStatsConsistency(t *testing.T) {
	t.Parallel()

	t.Run("default mode drops suppressed findings and does not count them", func(t *testing.T) {
		issues, metrics, errs := scanSource(t, md5Package("//#nosec G401"), scanOptions{})
		if errCount(errs) != 0 {
			t.Fatalf("unexpected errors: %v", errs)
		}
		if len(issues) != 0 {
			t.Fatalf("got %d issues, want 0", len(issues))
		}
		if metrics.NumFound != 0 {
			t.Fatalf("suppressed finding counted as found: %d", metrics.NumFound)
		}
		if metrics.NumNosec != 1 {
			t.Fatalf("got %d nosec directives, want 1", metrics.NumNosec)
		}
	})

	t.Run("show-ignored marks suppressed findings without counting them", func(t *testing.T) {
		conf := gosec.NewConfig()
		conf.SetGlobal(gosec.ShowIgnored, "true")
		issues, metrics, errs := scanSource(t, md5Package("//#nosec G401"), scanOptions{config: conf})
		if errCount(errs) != 0 {
			t.Fatalf("unexpected errors: %v", errs)
		}
		if len(issues) != 1 || !issues[0].NoSec {
			t.Fatalf("got %#v, want one issue flagged as nosec", issues)
		}
		if metrics.NumFound != 0 {
			t.Fatalf("suppressed finding counted as found: %d", metrics.NumFound)
		}
	})

	t.Run("tracked suppressions keep nosec flag and info consistent", func(t *testing.T) {
		issues, metrics, errs := scanSource(t, md5Package("//#nosec G401 -- ok"), scanOptions{trackSuppressions: true})
		if errCount(errs) != 0 {
			t.Fatalf("unexpected errors: %v", errs)
		}
		if len(issues) != 1 {
			t.Fatalf("got %d issues, want 1 (tracked suppression)", len(issues))
		}
		iss := issues[0]
		if !iss.NoSec {
			t.Fatalf("tracked suppressed issue is not flagged as nosec: %#v", iss)
		}
		if len(iss.Suppressions) != 1 || iss.Suppressions[0].Kind != "inSource" || iss.Suppressions[0].Justification != "ok" {
			t.Fatalf("inconsistent suppression info: %#v", iss.Suppressions)
		}
		if metrics.NumFound != 0 || metrics.NumNosec != 1 {
			t.Fatalf("inconsistent metrics: %#v", metrics)
		}
	})
}

// TestSSAAnalyzerNoSecSuppression checks that nosec directives and the
// invalid-directive handling apply to SSA-based analyzers exactly as they do
// to AST-based rules.
func TestSSAAnalyzerNoSecSuppression(t *testing.T) {
	t.Parallel()

	const src = `package main

import (
	"fmt"
	"math"
)

func main() {
	var a uint32 = math.MaxUint32
	b := int32(a) %s
	fmt.Println(b)
}
`

	t.Run("nosec suppresses SSA finding", func(t *testing.T) {
		issues, metrics, errs := scanSource(t, fmt.Sprintf(src, "//#nosec G115"), scanOptions{
			ruleIDs:     []string{"G101"}, // no AST rule fires on this source
			analyzerIDs: []string{"G115"},
		})
		if errCount(errs) != 0 {
			t.Fatalf("unexpected errors: %v", errs)
		}
		if len(issues) != 0 {
			t.Fatalf("got %d issues, want 0: %v", len(issues), issues)
		}
		if metrics.NumNosec != 1 || metrics.NumFound != 0 {
			t.Fatalf("inconsistent metrics: %#v", metrics)
		}
	})

	t.Run("malformed directive does not suppress SSA finding", func(t *testing.T) {
		issues, metrics, errs := scanSource(t, fmt.Sprintf(src, "//#nosec G1159"), scanOptions{
			ruleIDs:     []string{"G101"},
			analyzerIDs: []string{"G115"},
		})
		if errCount(errs) != 1 {
			t.Fatalf("got %d errors, want 1: %v", errCount(errs), errs)
		}
		if len(issues) != 1 {
			t.Fatalf("got %d issues, want 1: %v", len(issues), issues)
		}
		if metrics.NumNosec != 0 || metrics.NumFound != 1 {
			t.Fatalf("inconsistent metrics: %#v", metrics)
		}
	})
}
