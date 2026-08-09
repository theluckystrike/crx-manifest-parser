package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	crx "github.com/theluckystrike/crx-manifest-parser"
)

const mv3 = `{
  "manifest_version": 3,
  "name": "Audit Sample",
  "version": "2.1.0",
  "permissions": ["storage", "scripting"],
  "host_permissions": ["https://*.example.com/*"],
  "action": {"default_popup": "popup.html"},
  "background": {"service_worker": "sw.js"},
  "content_scripts": [{"matches": ["https://example.com/*"], "js": ["cs.js"]}],
  "content_security_policy": {"extension_pages": "script-src 'self'"}
}`

func TestBuildMV3(t *testing.T) {
	m, err := crx.ParseString(mv3)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	r := Build(m)
	if !r.Valid {
		t.Errorf("Valid = false, want true (%s)", r.ValidationError)
	}
	if !r.IsMV3 {
		t.Error("IsMV3 = false, want true")
	}
	if len(r.AllPermissions) != 3 {
		t.Errorf("AllPermissions = %v, want 3 entries", r.AllPermissions)
	}
	if r.BackgroundKind != "service_worker: sw.js" {
		t.Errorf("BackgroundKind = %q", r.BackgroundKind)
	}
	if r.ActionPopup != "popup.html" {
		t.Errorf("ActionPopup = %q", r.ActionPopup)
	}
	if r.CSP != "script-src 'self'" {
		t.Errorf("CSP = %q", r.CSP)
	}
	if len(r.ContentScripts) != 1 || r.ContentScripts[0] != "https://example.com/*" {
		t.Errorf("ContentScripts = %v", r.ContentScripts)
	}
}

func TestBuildInvalidVersion(t *testing.T) {
	m, err := crx.ParseString(`{"manifest_version":3,"name":"X","version":"not-a-version"}`)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	r := Build(m)
	if r.Valid {
		t.Error("Valid = true, want false for a bad version string")
	}
	if !strings.Contains(r.ValidationError, "invalid version") {
		t.Errorf("ValidationError = %q", r.ValidationError)
	}
}

func TestRunJSONExitZero(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "manifest.json")
	if err := os.WriteFile(p, []byte(mv3), 0o600); err != nil {
		t.Fatal(err)
	}
	var out, errb bytes.Buffer
	if code := run([]string{"-json", p}, &out, &errb); code != 0 {
		t.Fatalf("exit = %d, stderr = %s", code, errb.String())
	}
	var r Report
	if err := json.Unmarshal(out.Bytes(), &r); err != nil {
		t.Fatalf("output is not JSON: %v", err)
	}
	if r.Name != "Audit Sample" || r.Version != "2.1.0" {
		t.Errorf("decoded report = %+v", r)
	}
}

func TestRunTextAndUsage(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "manifest.json")
	if err := os.WriteFile(p, []byte(mv3), 0o600); err != nil {
		t.Fatal(err)
	}
	var out, errb bytes.Buffer
	if code := run([]string{p}, &out, &errb); code != 0 {
		t.Fatalf("exit = %d", code)
	}
	if !strings.Contains(out.String(), "permission count") {
		t.Errorf("text output missing permission count:\n%s", out.String())
	}
	out.Reset()
	errb.Reset()
	if code := run(nil, &out, &errb); code != 2 {
		t.Errorf("no-arg exit = %d, want 2", code)
	}
	if !strings.Contains(errb.String(), "usage:") {
		t.Errorf("missing usage line: %s", errb.String())
	}
}

func TestRunMissingFile(t *testing.T) {
	var out, errb bytes.Buffer
	if code := run([]string{filepath.Join(t.TempDir(), "nope.json")}, &out, &errb); code != 1 {
		t.Errorf("exit = %d, want 1", code)
	}
}
