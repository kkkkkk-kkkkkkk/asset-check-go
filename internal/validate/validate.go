// Package validate 只做纯校验与规范化：不碰文件、不碰标准输入输出。
// 这样表驱动单测可以直接调用，不必准备磁盘文件。
package validate

import (
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"
)

// 四个业务字段的规范名。CSV 表头会映射到这几个名字。
const (
	FieldIP         = "ip"
	FieldDeviceType = "device_type"
	FieldOwnerID    = "owner_id"
	FieldPort       = "port"
)

// Issue 是「问题报告」的一行。
type Issue struct {
	Line       int    // CSV 实际行号（表头是第 1 行）
	Column     string // 出问题的列名
	Severity   string // error / warning
	Value      string // 原始值
	Message    string // 人话描述
	Suggestion string // 建议改成什么（没有建议时为空）
}

// Normalized 是规范化后的一行。
type Normalized struct {
	IP         string
	DeviceType string
	OwnerID    string
	Port       int
	HasPort    bool
}

// Rules 是「我们给定的字段规则」，放在外部 JSON 里，改规则不用改代码。
type Rules struct {
	Columns           map[string]string `json:"columns"`
	DeviceTypes       []string          `json:"device_types"`
	DeviceTypeAliases map[string]string `json:"device_type_aliases"`
	OwnerIDPattern    string            `json:"owner_id_pattern"`
	PortOptional      bool              `json:"port_optional"`
	PortMin           int               `json:"port_min"`
	PortMax           int               `json:"port_max"`
}

// Decision 表示这一行最后的去处。
type Decision int

const (
	Keep    Decision = iota // 进规范化清单
	DropDup                 // 重复，丢掉
	Invalid                 // 有 error 级问题
)

// DefaultRules 是内置兜底规则，必须被显式覆盖成客户真实规则再投产。
func DefaultRules() *Rules {
	return &Rules{
		Columns: map[string]string{
			"ip": FieldIP, "ip地址": FieldIP, "ipaddress": FieldIP, "ipaddr": FieldIP,
			"设备类型": FieldDeviceType, "类型": FieldDeviceType, "type": FieldDeviceType,
			"devicetype": FieldDeviceType, "设备": FieldDeviceType,
			"负责人工号": FieldOwnerID, "工号": FieldOwnerID, "负责人": FieldOwnerID,
			"ownerid": FieldOwnerID, "owner": FieldOwnerID,
			"端口": FieldPort, "port": FieldPort,
		},
		DeviceTypes: []string{"防火墙", "交换机", "路由器", "服务器", "堡垒机", "负载均衡", "无线控制器", "WAF", "IDS", "IPS", "审计平台", "终端"},
		DeviceTypeAliases: map[string]string{
			"fw": "防火墙", "firewall": "防火墙",
			"sw": "交换机", "switch": "交换机",
			"rt": "路由器", "router": "路由器",
			"lb": "负载均衡",
		},
		OwnerIDPattern: `^[A-Za-z]{1,2}\d{3,6}$`,
		PortOptional:   false,
		PortMin:        1,
		PortMax:        65535,
	}
}

// LoadRules 读外部规则文件。文件里没写的字段用默认值补齐，便于只改想改的那几项。
func LoadRules(path string) (*Rules, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	base := DefaultRules()
	if err := json.Unmarshal(b, base); err != nil {
		return nil, fmt.Errorf("规则 JSON 解析失败: %w", err)
	}
	if base.OwnerIDPattern == "" {
		base.OwnerIDPattern = DefaultRules().OwnerIDPattern
	}
	if base.PortMax == 0 {
		base.PortMax = 65535
	}
	if base.PortMin == 0 {
		base.PortMin = 1
	}
	if len(base.Columns) == 0 {
		base.Columns = DefaultRules().Columns
	}
	return base, nil
}

// NormalizeHeader 把表头改成查找用的 key：去首尾空白、去内部空白、转小写。
func NormalizeHeader(s string) string {
	s = strings.Join(strings.Fields(s), "")
	return strings.ToLower(s)
}

// MapHeader 把 CSV 表头映射到四个业务字段，返回字段 -> 列下标。
func MapHeader(header []string, r *Rules) (map[string]int, error) {
	if r == nil {
		r = DefaultRules()
	}
	idx := make(map[string]int, 4)
	for i, h := range header {
		key := NormalizeHeader(h)
		if key == "" {
			continue
		}
		f, ok := r.Columns[key]
		if !ok {
			continue
		}
		if _, dup := idx[f]; dup {
			continue // 同一字段重复出现，取最左边那个
		}
		idx[f] = i
	}
	missing := make([]string, 0, 4)
	for _, f := range []string{FieldIP, FieldDeviceType, FieldOwnerID, FieldPort} {
		if _, ok := idx[f]; ok {
			continue
		}
		if f == FieldPort && r.PortOptional {
			continue
		}
		missing = append(missing, f)
	}
	if len(missing) > 0 {
		return idx, fmt.Errorf("表头缺少必需字段: %s（可在规则 JSON 的 columns 里加映射）", strings.Join(missing, ", "))
	}
	return idx, nil
}

// Validator 保存规则、编译好的正则，以及去重用的「首次出现行号」。
// 一个 CSV 用一个 Validator，跨行去重才成立。
type Validator struct {
	rules   *Rules
	ownerRE *regexp.Regexp
	seen    map[string]int
}

func NewValidator(r *Rules) (*Validator, error) {
	if r == nil {
		r = DefaultRules()
	}
	re, err := regexp.Compile(r.OwnerIDPattern)
	if err != nil {
		return nil, fmt.Errorf("owner_id_pattern 不是合法正则: %w", err)
	}
	return &Validator{rules: r, ownerRE: re, seen: make(map[string]int)}, nil
}

func (v *Validator) Rules() *Rules { return v.rules }

// Validate 校验一行。rec 的 key 是四个规范字段名，value 是原始单元格文本。
// 返回值：规范化后的行、问题列表、去向判定。
func (v *Validator) Validate(line int, rec map[string]string) (Normalized, []Issue, Decision) {
	var out Normalized
	issues := make([]Issue, 0, 4)
	hasErr := false

	// --- IP ---
	rawIP := strings.TrimSpace(rec[FieldIP])
	if rawIP == "" {
		issues = append(issues, Issue{line, "IP", "error", "", "IP 为空", ""})
		hasErr = true
	} else if ip, ok := NormalizeIP(rawIP); ok {
		out.IP = ip
	} else {
		sug := GuessIP(rawIP)
		msg := "不是合法 IPv4（四段 0-255、禁止前导零、不支持 IPv6）"
		if sug != "" {
			msg += "；看起来是 " + sug
		}
		issues = append(issues, Issue{line, "IP", "error", rawIP, msg, sug})
		hasErr = true
	}

	// --- 设备类型 ---
	rawDev := strings.TrimSpace(rec[FieldDeviceType])
	if rawDev == "" {
		issues = append(issues, Issue{line, "设备类型", "error", "", "设备类型为空", ""})
		hasErr = true
	} else if dev, ok := v.normalizeDevice(rawDev); ok {
		out.DeviceType = dev
	} else {
		issues = append(issues, Issue{line, "设备类型", "error", rawDev,
			"不在允许列表内: " + strings.Join(v.rules.DeviceTypes, " / "), ""})
		hasErr = true
	}

	// --- 负责人工号 ---
	rawOwner := strings.TrimSpace(rec[FieldOwnerID])
	if rawOwner == "" {
		issues = append(issues, Issue{line, "负责人工号", "error", "", "负责人工号为空", ""})
		hasErr = true
	} else if v.ownerRE.MatchString(rawOwner) {
		out.OwnerID = rawOwner
	} else {
		issues = append(issues, Issue{line, "负责人工号", "error", rawOwner,
			"不符合工号格式 " + v.rules.OwnerIDPattern, ""})
		hasErr = true
	}

	// --- 端口 ---
	rawPort := strings.TrimSpace(rec[FieldPort])
	if rawPort == "" {
		if v.rules.PortOptional {
			out.HasPort = false
		} else {
			issues = append(issues, Issue{line, "端口", "error", "", "端口为空", ""})
			hasErr = true
		}
	} else if p, ok := v.parsePort(rawPort); ok {
		out.Port = p
		out.HasPort = true
	} else {
		issues = append(issues, Issue{line, "端口", "error", rawPort,
			fmt.Sprintf("端口必须是 %d-%d 的整数", v.rules.PortMin, v.rules.PortMax), ""})
		hasErr = true
	}

	// --- 去重：只有 IP 与端口都干净时才判断，否则两行都不完整，比较没意义 ---
	if !hasErr && out.HasPort {
		key := out.IP + "|" + strconv.Itoa(out.Port)
		if prev, dup := v.seen[key]; dup {
			issues = append(issues, Issue{line, "IP/端口", "warning", out.IP + ":" + strconv.Itoa(out.Port),
				fmt.Sprintf("与第 %d 行的 IP+端口 重复，按首次出现保留", prev), ""})
			return out, issues, DropDup
		}
		v.seen[key] = line
	}

	if hasErr {
		return out, issues, Invalid
	}
	return out, issues, Keep
}

func (v *Validator) normalizeDevice(raw string) (string, bool) {
	if len(v.rules.DeviceTypes) == 0 {
		return raw, true
	}
	key := NormalizeHeader(raw)
	if alias, ok := v.rules.DeviceTypeAliases[key]; ok {
		return alias, true
	}
	for _, d := range v.rules.DeviceTypes {
		if strings.EqualFold(d, raw) {
			return d, true
		}
	}
	return raw, false
}

func (v *Validator) parsePort(raw string) (int, bool) {
	if raw == "" {
		return 0, false
	}
	for _, c := range raw {
		if c < '0' || c > '9' {
			return 0, false
		}
	}
	p, err := strconv.Atoi(raw)
	if err != nil {
		return 0, false
	}
	if p < v.rules.PortMin || p > v.rules.PortMax {
		return 0, false
	}
	return p, true
}

// NormalizeIP 校验并规范化 IPv4：去空白、每段不许前导零、0-255。
func NormalizeIP(s string) (string, bool) {
	s = strings.TrimSpace(s)
	if s == "" || strings.Contains(s, ":") || strings.Contains(s, "/") {
		return "", false
	}
	parts := strings.Split(s, ".")
	if len(parts) != 4 {
		return "", false
	}
	out := make([]string, 0, 4)
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			return "", false
		}
		if len(p) > 1 && p[0] == '0' {
			return "", false // 0192 这类前导零有八进制歧义，一律判错
		}
		for _, c := range p {
			if c < '0' || c > '9' {
				return "", false
			}
		}
		if len(p) > 3 {
			return "", false
		}
		n, err := strconv.Atoi(p)
		if err != nil || n > 255 {
			return "", false
		}
		out = append(out, strconv.Itoa(n))
	}
	return strings.Join(out, "."), true
}

// GuessIP 尝试给一个「最像的修正值」：去掉每段前导零、裁剪多余段。
// 猜不出来就返回空串——宁可没有建议，也不给错建议。
func GuessIP(s string) string {
	s = strings.TrimSpace(s)
	if s == "" || strings.Contains(s, ":") {
		return ""
	}
	parts := strings.Split(s, ".")
	if len(parts) != 4 {
		return ""
	}
	out := make([]string, 0, 4)
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			return ""
		}
		for len(p) > 1 && p[0] == '0' {
			p = p[1:]
		}
		for _, c := range p {
			if c < '0' || c > '9' {
				return ""
			}
		}
		n, err := strconv.Atoi(p)
		if err != nil || n > 255 {
			return ""
		}
		out = append(out, strconv.Itoa(n))
	}
	fixed := strings.Join(out, ".")
	if fixed == s {
		return ""
	}
	return fixed
}

// Row 把规范化结果转成 CSV 的四列。端口缺失时留空，不写 0。
func (n Normalized) Row() []string {
	port := ""
	if n.HasPort {
		port = strconv.Itoa(n.Port)
	}
	return []string{n.IP, n.DeviceType, n.OwnerID, port}
}
