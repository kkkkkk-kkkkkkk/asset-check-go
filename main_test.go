package main

import (
	"bytes"
	"encoding/csv"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// 造一份「格式乱、错误多」的样本，覆盖：前导零、超范围、重复行、空行、全空字段、合法别名。
const messyCSV = `IP,设备类型,负责人工号,端口
192.168.001.010,防火墙,A1234,443
10.0.0.5,交换机,B2001,22
10.0.0.5,交换机,B2001,22
 10.0.0.6 ,  FW , A5678 ,8080
10.0.0.300,路由器,D4003,0
,,,
172.16.0.1,交换机,AB12345,22
`

func writeTemp(t *testing.T, name, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func readCSVFile(t *testing.T, path string) [][]string {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	r := csv.NewReader(f)
	rows, err := r.ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	return rows
}

func TestRunNonStrict(t *testing.T) {
	in := writeTemp(t, "in.csv", messyCSV)
	dir := t.TempDir()
	out := filepath.Join(dir, "norm.csv")
	iss := filepath.Join(dir, "issues.csv")

	var stdout, stderr bytes.Buffer
	code := run([]string{"-in", in, "-out", out, "-issues", iss}, &stdout, &stderr)
	if code != exitOK {
		t.Fatalf("non-strict exit = %d, stderr=%s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "输入行数 7") {
		t.Fatalf("summary missing row count: %s", stdout.String())
	}

	norm := readCSVFile(t, out)
	if len(norm) != 4 { // 表头 + 3 行通过
		t.Fatalf("normalized rows = %d, want 4 (%v)", len(norm), norm)
	}
	if norm[1][0] != "10.0.0.5" || norm[2][0] != "10.0.0.6" || norm[3][0] != "172.16.0.1" {
		t.Fatalf("unexpected normalized order: %v", norm)
	}
	if norm[2][1] != "防火墙" {
		t.Fatalf("alias FW should normalize to 防火墙, got %q", norm[2][1])
	}
	if norm[2][3] != "8080" {
		t.Fatalf("port should be 8080, got %q", norm[2][3])
	}

	issues := readCSVFile(t, iss)
	if len(issues) < 8 {
		t.Fatalf("issues = %d rows, want >= 8", len(issues))
	}
	if issues[0][0] != "行号" || issues[0][5] != "建议值" {
		t.Fatalf("issues header wrong: %v", issues[0])
	}
	// 前导零那行必须给建议值
	foundSuggest := false
	for _, r := range issues[1:] {
		if r[0] == "2" && r[1] == "IP" && r[5] == "192.168.1.10" {
			foundSuggest = true
		}
	}
	if !foundSuggest {
		t.Fatalf("expected suggestion 192.168.1.10 for line 2, got %v", issues)
	}
}

func TestRunStrictExitCode(t *testing.T) {
	in := writeTemp(t, "in.csv", messyCSV)
	dir := t.TempDir()
	var stdout, stderr bytes.Buffer
	code := run([]string{
		"-in", in,
		"-out", filepath.Join(dir, "n.csv"),
		"-issues", filepath.Join(dir, "i.csv"),
		"-strict",
	}, &stdout, &stderr)
	if code != exitIssues {
		t.Fatalf("strict exit = %d, want %d (stderr=%s)", code, exitIssues, stderr.String())
	}
}

func TestRunCleanInput(t *testing.T) {
	clean := "IP,设备类型,负责人工号,端口\n10.0.0.1,交换机,A1234,22\n"
	in := writeTemp(t, "clean.csv", clean)
	dir := t.TempDir()
	var stdout, stderr bytes.Buffer
	code := run([]string{
		"-in", in,
		"-out", filepath.Join(dir, "n.csv"),
		"-issues", filepath.Join(dir, "i.csv"),
		"-strict",
	}, &stdout, &stderr)
	if code != exitOK {
		t.Fatalf("clean input strict should exit 0, got %d", code)
	}
	issues := readCSVFile(t, filepath.Join(dir, "i.csv"))
	if len(issues) != 1 {
		t.Fatalf("expected header-only issues file, got %d rows", len(issues))
	}
}

func TestRunUsageErrors(t *testing.T) {
	dir := t.TempDir()
	var stdout, stderr bytes.Buffer

	if code := run([]string{"-out", filepath.Join(dir, "n.csv")}, &stdout, &stderr); code != exitUsage {
		t.Fatalf("missing -in should exit %d, got %d", exitUsage, code)
	}

	badHeader := "名称,地址,编号\n防火墙,10.0.0.1,443\n"
	in := writeTemp(t, "bad.csv", badHeader)
	if code := run([]string{"-in", in, "-out", filepath.Join(dir, "n.csv"), "-issues", filepath.Join(dir, "i.csv")}, &stdout, &stderr); code != exitUsage {
		t.Fatalf("unmapped header should exit %d, got %d", exitUsage, code)
	}

	in2 := filepath.Join(dir, "missing.csv")
	if code := run([]string{"-in", in2, "-out", filepath.Join(dir, "n.csv"), "-issues", filepath.Join(dir, "i.csv")}, &stdout, &stderr); code != exitUsage {
		t.Fatalf("missing file should exit %d, got %d", exitUsage, code)
	}
}

func TestRunWithRulesFile(t *testing.T) {
	rulesBody := `{"owner_id_pattern":"^E\\d{4}$","port_min":1000,"port_max":2000}`
	rules := writeTemp(t, "rules.json", rulesBody)
	in := writeTemp(t, "in.csv", "IP,设备类型,负责人工号,端口\n10.0.0.1,交换机,E1234,1500\n")
	dir := t.TempDir()
	var stdout, stderr bytes.Buffer
	code := run([]string{
		"-in", in,
		"-rules", rules,
		"-out", filepath.Join(dir, "n.csv"),
		"-issues", filepath.Join(dir, "i.csv"),
		"-strict",
	}, &stdout, &stderr)
	if code != exitOK {
		t.Fatalf("rules-compliant row should pass strict, got %d (stderr=%s)", code, stderr.String())
	}
}
