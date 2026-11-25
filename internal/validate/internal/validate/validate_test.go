package validate

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestNormalizeIP(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
		ok   bool
	}{
		{"normal", "192.168.1.1", "192.168.1.1", true},
		{"spaces around", " 10.0.0.1 ", "10.0.0.1", true},
		{"lower bound", "0.0.0.0", "0.0.0.0", true},
		{"upper bound", "255.255.255.255", "255.255.255.255", true},
		{"leading zero", "192.168.01.1", "", false},
		{"out of range", "256.1.1.1", "", false},
		{"three octets", "10.0.0", "", false},
		{"five octets", "10.0.0.1.1", "", false},
		{"ipv6", "::1", "", false},
		{"cidr", "10.0.0.0/24", "", false},
		{"empty", "", "", false},
		{"letters", "a.b.c.d", "", false},
		{"negative", "1.2.3.-4", "", false},
		{"inner space tolerated", "10.0 .0.1", "10.0.0.1", true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, ok := NormalizeIP(c.in)
			if ok != c.ok {
				t.Fatalf("NormalizeIP(%q) ok=%v, want %v", c.in, ok, c.ok)
			}
			if got != c.want {
				t.Fatalf("NormalizeIP(%q) = %q, want %q", c.in, got, c.want)
			}
		})
	}
}

func TestGuessIP(t *testing.T) {
	cases := []struct{ in, want string }{
		{"192.168.01.1", "192.168.1.1"},
		{"010.000.000.001", "10.0.0.1"},
		{"256.1.1.1", ""},
		{"10.0.0", ""},
		{"::1", ""},
		{"192.168.1.1", ""},
	}
	for _, c := range cases {
		if got := GuessIP(c.in); got != c.want {
			t.Fatalf("GuessIP(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestMapHeader(t *testing.T) {
	rules := DefaultRules()
	cases := []struct {
		name    string
		header  []string
		wantErr string
	}{
		{"canonical", []string{"IP", "设备类型", "负责人工号", "端口"}, ""},
		{"alias and space", []string{" IP地址 ", "类型", "工号", "Port"}, ""},
		{"case insensitive", []string{"ip", "type", "ownerid", "port"}, ""},
		{"missing owner", []string{"IP", "设备类型", "端口"}, "owner_id"},
		{"missing ip", []string{"设备类型", "负责人工号", "端口"}, "ip"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			idx, err := MapHeader(c.header, rules)
			if c.wantErr == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				for _, f := range []string{FieldIP, FieldDeviceType, FieldOwnerID, FieldPort} {
					if _, ok := idx[f]; !ok {
						t.Fatalf("field %s not mapped", f)
					}
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), c.wantErr) {
				t.Fatalf("want error containing %q, got %v", c.wantErr, err)
			}
		})
	}
}

func TestValidateRows(t *testing.T) {
	cases := []struct {
		name     string
		rec      map[string]string
		wantDec  Decision
		wantIss  int
		wantErr  bool // 是否有 error 级问题
		wantIP   string
		wantPort int
		wantDev  string
	}{
		{
			name:     "clean row",
			rec:      map[string]string{FieldIP: "10.0.0.5", FieldDeviceType: "交换机", FieldOwnerID: "B2001", FieldPort: "22"},
			wantDec:  Keep,
			wantIP:   "10.0.0.5",
			wantPort: 22,
			wantDev:  "交换机",
		},
		{
			name:     "ip leading zero",
			rec:      map[string]string{FieldIP: "192.168.001.010", FieldDeviceType: "防火墙", FieldOwnerID: "A1234", FieldPort: "443"},
			wantDec:  Invalid,
			wantIss:  1,
			wantErr:  true,
			wantPort: 443,
		},
		{
			name:    "ip empty",
			rec:     map[string]string{FieldIP: "", FieldDeviceType: "路由器", FieldOwnerID: "A1234", FieldPort: "80"},
			wantDec: Invalid,
			wantIss: 1,
			wantErr: true,
		},
		{
			name:    "device unknown",
			rec:     map[string]string{FieldIP: "10.1.1.1", FieldDeviceType: "微波炉", FieldOwnerID: "A1234", FieldPort: "80"},
			wantDec: Invalid,
			wantIss: 1,
			wantErr: true,
		},
		{
			name:     "device alias",
			rec:      map[string]string{FieldIP: "10.1.1.1", FieldDeviceType: "FW", FieldOwnerID: "A1234", FieldPort: "80"},
			wantDec:  Keep,
			wantDev:  "防火墙",
			wantPort: 80,
		},
		{
			name:    "owner no letters",
			rec:     map[string]string{FieldIP: "10.1.1.1", FieldDeviceType: "服务器", FieldOwnerID: "1234", FieldPort: "80"},
			wantDec: Invalid,
			wantIss: 1,
			wantErr: true,
		},
		{
			name:    "owner empty",
			rec:     map[string]string{FieldIP: "10.1.1.1", FieldDeviceType: "服务器", FieldOwnerID: "", FieldPort: "80"},
			wantDec: Invalid,
			wantIss: 1,
			wantErr: true,
		},
		{
			name:    "port zero",
			rec:     map[string]string{FieldIP: "10.1.1.1", FieldDeviceType: "服务器", FieldOwnerID: "A1234", FieldPort: "0"},
			wantDec: Invalid,
			wantIss: 1,
			wantErr: true,
		},
		{
			name:    "port too big",
			rec:     map[string]string{FieldIP: "10.1.1.1", FieldDeviceType: "服务器", FieldOwnerID: "A1234", FieldPort: "65536"},
			wantDec: Invalid,
			wantIss: 1,
			wantErr: true,
		},
		{
			name:    "port not a number",
			rec:     map[string]string{FieldIP: "10.1.1.1", FieldDeviceType: "服务器", FieldOwnerID: "A1234", FieldPort: "abc"},
			wantDec: Invalid,
			wantIss: 1,
			wantErr: true,
		},
		{
			name:     "port padded",
			rec:      map[string]string{FieldIP: "10.1.1.1", FieldDeviceType: "服务器", FieldOwnerID: "A1234", FieldPort: " 80 "},
			wantDec:  Keep,
			wantPort: 80,
		},
		{
			name:    "all empty row",
			rec:     map[string]string{},
			wantDec: Invalid,
			wantIss: 4,
			wantErr: true,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			// 每个用例用独立的 Validator：去重状态不能跨用例累积，否则互相污染
			v, err := NewValidator(DefaultRules())
			if err != nil {
				t.Fatal(err)
			}
			out, issues, dec := v.Validate(2, c.rec)
			if dec != c.wantDec {
				t.Fatalf("decision = %v, want %v", dec, c.wantDec)
			}
			if len(issues) != c.wantIss {
				t.Fatalf("issues = %d (%v), want %d", len(issues), issues, c.wantIss)
			}
			hasErr := false
			for _, it := range issues {
				if it.Severity == "error" {
					hasErr = true
				}
			}
			if hasErr != c.wantErr {
				t.Fatalf("hasErr = %v, want %v", hasErr, c.wantErr)
			}
			if c.wantIP != "" && out.IP != c.wantIP {
				t.Fatalf("ip = %q, want %q", out.IP, c.wantIP)
			}
			if c.wantDev != "" && out.DeviceType != c.wantDev {
				t.Fatalf("device = %q, want %q", out.DeviceType, c.wantDev)
			}
			if c.wantPort != 0 && out.Port != c.wantPort {
				t.Fatalf("port = %d, want %d", out.Port, c.wantPort)
			}
		})
	}
}

func TestDedupeAcrossRows(t *testing.T) {
	v, err := NewValidator(DefaultRules())
	if err != nil {
		t.Fatal(err)
	}
	rec := map[string]string{FieldIP: "10.0.0.5", FieldDeviceType: "交换机", FieldOwnerID: "B2001", FieldPort: "22"}

	if _, _, dec := v.Validate(2, rec); dec != Keep {
		t.Fatalf("first occurrence should be kept, got %v", dec)
	}
	out, issues, dec := v.Validate(3, rec)
	if dec != DropDup {
		t.Fatalf("second occurrence should be dropped, got %v", dec)
	}
	if len(issues) != 1 || issues[0].Severity != "warning" {
		t.Fatalf("want one warning, got %v", issues)
	}
	if !strings.Contains(issues[0].Message, "第 2 行") {
		t.Fatalf("warning should point to line 2, got %q", issues[0].Message)
	}
	if out.Port != 22 {
		t.Fatalf("port = %d, want 22", out.Port)
	}
	// 同一 IP 不同端口不算重复
	other := map[string]string{FieldIP: "10.0.0.5", FieldDeviceType: "交换机", FieldOwnerID: "B2001", FieldPort: "443"}
	if _, _, dec := v.Validate(4, other); dec != Keep {
		t.Fatalf("different port should be kept, got %v", dec)
	}
}

func TestNormalizedKeyUsesNormalizedIP(t *testing.T) {
	v, err := NewValidator(DefaultRules())
	if err != nil {
		t.Fatal(err)
	}
	// 10.0.0.5 与 10.0.0.05 前者合法后者非法，用 10.0.0.5 / 10.0.0.5 才叫真重复；
	// 这里验证「首尾空格不影响去重」。
	a := map[string]string{FieldIP: "10.0.0.5", FieldDeviceType: "交换机", FieldOwnerID: "B2001", FieldPort: "22"}
	b := map[string]string{FieldIP: " 10.0.0.5 ", FieldDeviceType: "交换机 ", FieldOwnerID: " B2001", FieldPort: "22 "}
	if _, _, dec := v.Validate(2, a); dec != Keep {
		t.Fatalf("first should be kept, got %v", dec)
	}
	if _, _, dec := v.Validate(3, b); dec != DropDup {
		t.Fatalf("spaces should not defeat dedupe, got %v", dec)
	}
}

func TestPortOptional(t *testing.T) {
	r := DefaultRules()
	r.PortOptional = true
	v, err := NewValidator(r)
	if err != nil {
		t.Fatal(err)
	}
	out, issues, dec := v.Validate(2, map[string]string{
		FieldIP: "10.0.0.5", FieldDeviceType: "交换机", FieldOwnerID: "B2001", FieldPort: "",
	})
	if dec != Keep {
		t.Fatalf("decision = %v, want Keep", dec)
	}
	if len(issues) != 0 {
		t.Fatalf("want no issues, got %v", issues)
	}
	if out.HasPort {
		t.Fatal("HasPort should be false")
	}
	rows := out.Row()
	if rows[3] != "" {
		t.Fatalf("port column should be empty, got %q", rows[3])
	}
}

func TestLoadRulesOverrides(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "rules.json")
	body := `{"owner_id_pattern":"^E\\d{4}$","port_min":1000,"port_max":2000,"device_types":["交换机"]}`
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	r, err := LoadRules(path)
	if err != nil {
		t.Fatal(err)
	}
	if r.OwnerIDPattern != `^E\d{4}$` {
		t.Fatalf("pattern not overridden: %q", r.OwnerIDPattern)
	}
	if r.PortMin != 1000 || r.PortMax != 2000 {
		t.Fatalf("port range not overridden: %d-%d", r.PortMin, r.PortMax)
	}
	// 没写的字段要落回默认
	if len(r.Columns) == 0 {
		t.Fatal("columns should fall back to defaults")
	}

	v, err := NewValidator(r)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, dec := v.Validate(2, map[string]string{
		FieldIP: "10.0.0.1", FieldDeviceType: "交换机", FieldOwnerID: "E1234", FieldPort: "1500",
	}); dec != Keep {
		t.Fatalf("decision = %v, want Keep", dec)
	}
	if _, issues, dec := v.Validate(3, map[string]string{
		FieldIP: "10.0.0.2", FieldDeviceType: "交换机", FieldOwnerID: "A1234", FieldPort: "1500",
	}); dec != Invalid || len(issues) != 1 {
		t.Fatalf("owner id outside custom pattern should be invalid, got %v %v", dec, issues)
	}
	if _, _, dec := v.Validate(4, map[string]string{
		FieldIP: "10.0.0.3", FieldDeviceType: "交换机", FieldOwnerID: "E1235", FieldPort: "999",
	}); dec != Invalid {
		t.Fatalf("port below custom min should be invalid, got %v", dec)
	}
}
