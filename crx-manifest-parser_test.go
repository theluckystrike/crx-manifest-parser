package crxmanifestparser

import (
	"encoding/json"
	"testing"
)

func TestParseMV3Basic(t *testing.T) {
	src := `{
		"manifest_version": 3,
		"name": "Test Ext",
		"version": "1.0.0",
		"description": "A test extension.",
		"permissions": ["storage", "tabs"],
		"host_permissions": ["https://*.example.com/*"],
		"action": {"default_popup": "popup.html", "default_title": "Hi"},
		"background": {"service_worker": "bg.js", "type": "module"},
		"icons": {"16": "icon16.png", "128": "icon128.png"}
	}`
	m, err := ParseString(src)
	if err != nil {
		t.Fatalf("ParseString: %v", err)
	}
	if m.ManifestVersion != 3 {
		t.Errorf("ManifestVersion = %d, want 3", m.ManifestVersion)
	}
	if m.Name != "Test Ext" {
		t.Errorf("Name = %q, want \"Test Ext\"", m.Name)
	}
	if m.Version != "1.0.0" {
		t.Errorf("Version = %q, want 1.0.0", m.Version)
	}
	if len(m.Permissions) != 2 || m.Permissions[0] != "storage" {
		t.Errorf("Permissions = %v", m.Permissions)
	}
	if len(m.HostPermissions) != 1 {
		t.Errorf("HostPermissions = %v", m.HostPermissions)
	}
	if m.Action == nil || m.Action.DefaultPopup != "popup.html" {
		t.Errorf("Action wrong: %+v", m.Action)
	}
	if m.Background == nil || m.Background.ServiceWorker != "bg.js" || m.Background.Type != "module" {
		t.Errorf("Background wrong: %+v", m.Background)
	}
	if m.Icons["128"] != "icon128.png" {
		t.Errorf("Icons[128] = %q", m.Icons["128"])
	}
	if !m.IsManifestV3() {
		t.Error("IsManifestV3 = false, want true")
	}
}

func TestParseMV2BackgroundScripts(t *testing.T) {
	src := `{
		"manifest_version": 2,
		"name": "MV2",
		"version": "0.1",
		"background": {"scripts": ["bg1.js", "bg2.js"], "persistent": false},
		"browser_action": {"default_popup": "p.html"}
	}`
	m, err := ParseString(src)
	if err != nil {
		t.Fatalf("ParseString: %v", err)
	}
	if m.ManifestVersion != 2 {
		t.Errorf("ManifestVersion = %d, want 2", m.ManifestVersion)
	}
	if m.Background == nil || len(m.Background.Scripts) != 2 {
		t.Errorf("Background.Scripts = %v", m.Background)
	}
	if m.EffectiveAction() != m.BrowserAction {
		t.Error("EffectiveAction should fall back to browser_action on MV2")
	}
}

func TestValidateRequired(t *testing.T) {
	cases := []struct {
		name    string
		json    string
		wantErr string
	}{
		{"missing name", `{"version":"1.0"}`, "name"},
		{"missing version", `{"name":"x"}`, "version"},
		{"bad version", `{"name":"x","version":"1.2.x"}`, "invalid version"},
		{"bad version range", `{"name":"x","version":"99999"}`, "invalid version"},
		{"bad manifest_version", `{"name":"x","version":"1.0","manifest_version":5}`, "manifest_version"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			m, err := ParseString(c.json)
			if err != nil {
				t.Fatalf("ParseString: %v", err)
			}
			err = m.Validate()
			if err == nil {
				t.Fatalf("Validate returned nil, want error containing %q", c.wantErr)
			}
		})
	}
}

func TestValidateOK(t *testing.T) {
	m, err := ParseString(`{"manifest_version":3,"name":"ok","version":"2.3.4"}`)
	if err != nil {
		t.Fatal(err)
	}
	if err := m.Validate(); err != nil {
		t.Errorf("Validate returned error for valid manifest: %v", err)
	}
}

func TestEmptyInput(t *testing.T) {
	_, err := ParseBytes(nil)
	if err == nil {
		t.Error("ParseBytes(nil) returned nil error")
	}
}

func TestInvalidJSON(t *testing.T) {
	_, err := ParseString(`{not json`)
	if err == nil {
		t.Error("ParseString(invalid) returned nil error")
	}
}

func TestContentScriptsAndCommands(t *testing.T) {
	src := `{
		"manifest_version": 3,
		"name": "x",
		"version": "1.0",
		"content_scripts": [{
			"matches": ["https://*/*"],
			"js": ["cs.js"],
			"run_at": "document_idle",
			"all_frames": true
		}],
		"commands": {
			"do-thing": {"description": "d", "suggested_key": {"default": "Ctrl+Shift+Y"}}
		}
	}`
	m, err := ParseString(src)
	if err != nil {
		t.Fatal(err)
	}
	if len(m.ContentScripts) != 1 || m.ContentScripts[0].RunAt != "document_idle" {
		t.Errorf("ContentScripts wrong: %+v", m.ContentScripts)
	}
	if m.Commands["do-thing"].SuggestedKey["default"] != "Ctrl+Shift+Y" {
		t.Errorf("Commands wrong: %+v", m.Commands)
	}
}

func TestCSPString(t *testing.T) {
	src := `{
		"manifest_version": 3,
		"name": "x",
		"version": "1.0",
		"content_security_policy": {"extension_pages": "script-src 'self'"}
	}`
	m, err := ParseString(src)
	if err != nil {
		t.Fatal(err)
	}
	if got := m.ContentSecurityPolicyString(); got != "script-src 'self'" {
		t.Errorf("CSP = %q", got)
	}
}

func TestAllPermissions(t *testing.T) {
	m, _ := ParseString(`{"name":"x","version":"1.0","permissions":["a"],"host_permissions":["b","c"]}`)
	all := m.AllPermissions()
	if len(all) != 3 || all[2] != "c" {
		t.Errorf("AllPermissions = %v", all)
	}
}

func TestRawRetained(t *testing.T) {
	src := `{"name":"x","version":"1.0","custom_field":42}`
	m, err := ParseString(src)
	if err != nil {
		t.Fatal(err)
	}
	rawVal, ok := m.Raw["custom_field"]
	if !ok {
		t.Fatal("Raw should retain custom_field")
	}
	var n int
	if err := json.Unmarshal(rawVal, &n); err != nil || n != 42 {
		t.Errorf("custom_field unmarshal: n=%d err=%v", n, err)
	}
}

func TestIsValidVersion(t *testing.T) {
	good := []string{"1", "1.0", "1.2.3", "1.2.3.4", "0.0.0.0", "65535"}
	bad := []string{"", "1.", ".1", "1.2.3.4.5", "1.x", "99999", "1.-2", "1.2.3."}
	for _, v := range good {
		if !isValidVersion(v) {
			t.Errorf("isValidVersion(%q) = false, want true", v)
		}
	}
	for _, v := range bad {
		if isValidVersion(v) {
			t.Errorf("isValidVersion(%q) = true, want false", v)
		}
	}
}

func TestSettingsOverrides(t *testing.T) {
	src := `{
		"name":"x","version":"1.0",
		"chrome_settings_overrides": {
			"homepage": "https://newtab.example",
			"search_provider": {"name":"S","search_url":"https://s.example/?q={searchTerms}","is_default":true}
		}
	}`
	m, err := ParseString(src)
	if err != nil {
		t.Fatal(err)
	}
	if m.ChromeSettingsOverrides == nil || m.ChromeSettingsOverrides.Homepage != "https://newtab.example" {
		t.Errorf("SettingsOverrides wrong: %+v", m.ChromeSettingsOverrides)
	}
	if m.ChromeSettingsOverrides.Search == nil || !m.ChromeSettingsOverrides.Search.IsDefault {
		t.Error("SearchProvider.IsDefault not parsed")
	}
}
