package main

import (
	"encoding/csv"
	"flag"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"

	"assetcheck/internal/validate"
)

const (
	exitOK     = 0
	exitIssues = 1 // strict 模式下有 error
	exitUsage  = 2 // 参数/文件/规则问题
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

// run 是可测试的入口：不直接调 os.Exit，方便单测断言退出码。
func run(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("asset-check", flag.ContinueOnError)
	fs.SetOutput(stderr)
	in := fs.String("in", "", "输入资产清单 CSV 路径（必填）")
	outPath := fs.String("out", "normalized.csv", "规范化清单输出路径")
	issuesPath := fs.String("issues", "issues.csv", "问题报告输出路径")
	rulesPath := fs.String("rules", "", "规则 JSON 路径，省略则用内置默认规则")
	strict := fs.Bool("strict", false, "严格模式：存在 error 级问题时退出码为 1")
	keepInvalid := fs.Bool("keep-invalid", false, "把有错误的行也写进规范化清单（默认只写通过的行）")
	quiet := fs.Bool("quiet", false, "不打印摘要")
	if err := fs.Parse(args); err != nil {
		return exitUsage
	}
	if *in == "" {
		fmt.Fprintln(stderr, "缺少 -in 参数（输入 CSV 路径）")
		return exitUsage
	}

	rules := validate.DefaultRules()
	if *rulesPath != "" {
		r, err := validate.LoadRules(*rulesPath)
		if err != nil {
			fmt.Fprintf(stderr, "读取规则失败: %v\n", err)
			return exitUsage
		}
		rules = r
	}

	rows, err := readCSV(*in)
	if err != nil {
		fmt.Fprintf(stderr, "读取输入失败: %v\n", err)
		return exitUsage
	}
	if len(rows) == 0 {
		fmt.Fprintln(stderr, "输入文件是空的")
		return exitUsage
	}

	idx, err := validate.MapHeader(rows[0], rules)
	if err != nil {
		fmt.Fprintf(stderr, "表头映射失败: %v\n", err)
		return exitUsage
	}
	v, err := validate.NewValidator(rules)
	if err != nil {
		fmt.Fprintf(stderr, "规则无效: %v\n", err)
		return exitUsage
	}

	normRows := make([][]string, 0, len(rows)-1)
	allIssues := make([]validate.Issue, 0, 16)
	var total, kept, dups, errs, warns int

	for i, row := range rows[1:] {
		line := i + 2 // 表头占第 1 行
		total++
		rec := make(map[string]string, 4)
		for field, ci := range idx {
			rec[field] = cell(row, ci)
		}
		n, issues, dec := v.Validate(line, rec)
		allIssues = append(allIssues, issues...)
		for _, it := range issues {
			if it.Severity == "error" {
				errs++
			} else {
				warns++
			}
		}
		switch dec {
		case validate.Keep:
			kept++
			normRows = append(normRows, n.Row())
		case validate.DropDup:
			dups++
		case validate.Invalid:
			if *keepInvalid {
				normRows = append(normRows, n.Row())
			}
		}
	}

	if err := writeCSV(*outPath, []string{"IP", "设备类型", "负责人工号", "端口"}, normRows); err != nil {
		fmt.Fprintf(stderr, "写规范化清单失败: %v\n", err)
		return exitUsage
	}
	if err := writeIssues(*issuesPath, allIssues); err != nil {
		fmt.Fprintf(stderr, "写问题报告失败: %v\n", err)
		return exitUsage
	}

	if !*quiet {
		fmt.Fprintf(stdout, "输入行数 %d，通过 %d，重复丢弃 %d，error %d，warning %d\n", total, kept, dups, errs, warns)
		fmt.Fprintf(stdout, "规范化清单 → %s\n问题报告 → %s\n", *outPath, *issuesPath)
	}

	if *strict && errs > 0 {
		return exitIssues
	}
	return exitOK
}

// readCSV 只负责把文件变成字符串矩阵，不做任何业务判断。
func readCSV(path string) ([][]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	r := csv.NewReader(f)
	r.FieldsPerRecord = -1
	r.LazyQuotes = true
	r.TrimLeadingSpace = true
	return r.ReadAll()
}

func writeCSV(path string, header []string, rows [][]string) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	w := csv.NewWriter(f)
	if err := w.Write(header); err != nil {
		return err
	}
	for _, r := range rows {
		if err := w.Write(r); err != nil {
			return err
		}
	}
	w.Flush()
	return w.Error()
}

func writeIssues(path string, issues []validate.Issue) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	w := csv.NewWriter(f)
	if err := w.Write([]string{"行号", "列名", "严重度", "原始值", "问题描述", "建议值"}); err != nil {
		return err
	}
	for _, it := range issues {
		row := []string{
			strconv.Itoa(it.Line),
			it.Column,
			it.Severity,
			it.Value,
			it.Message,
			it.Suggestion,
		}
		if err := w.Write(row); err != nil {
			return err
		}
	}
	w.Flush()
	return w.Error()
}

func cell(row []string, i int) string {
	if i < 0 || i >= len(row) {
		return ""
	}
	return strings.TrimSpace(row[i])
}
