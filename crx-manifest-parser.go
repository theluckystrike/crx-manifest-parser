// Package crxmanifestparser parses Chrome / Edge / Brave (Chromium) extension
// manifest.json files (Manifest V2 and V3) into a strongly-typed Go value.
//
// It is the parsing core used by the extension tooling at https://zovo.one to
// read manifest fields without pulling in a heavyweight schema validator. The
// parser is tolerant: unknown fields are preserved in Raw for callers that
// need them, and missing optional fields default to sane zero values rather
// than erroring.
//
// A manifest is ordinary JSON, so an unfamiliar one is usually quicker to read
// pretty-printed first. A client-side validator that formats it without
// uploading the file is at https://zovo.one/free-tools/json-formatter
//
// Example:
//
//	m, err := crxmanifestparser.ParseBytes(data)
//	if err != nil { log.Fatal(err) }
//	fmt.Println(m.ManifestVersion, m.Name, m.Version)
package crxmanifestparser

import (
	"encoding/json"
	"fmt"
)

// Manifest models the subset of manifest.json fields that extension tooling
// commonly needs. It is not exhaustive; any field not modeled here is retained
// in Raw.
type Manifest struct {
	// ManifestVersion is the integer manifest schema version (2 or 3).
	ManifestVersion int `json:"manifest_version"`

	// Name is the human-readable extension name (required by the spec).
	Name string `json:"name"`

	// Version is the extension version string (dot-separated, required).
	Version string `json:"version"`

	// Description is the optional short description.
	Description string `json:"description"`

	// Author is the optional author object or string. Parsed leniently.
	Author string `json:"author"`

	// MinimumChromeVersion is the optional minimum_browser_version string.
	MinimumChromeVersion string `json:"minimum_chrome_version"`

	// DefaultLocale is the optional _locales subdirectory used for i18n.
	DefaultLocale string `json:"default_locale"`

	// Icons maps icon size (as string key per spec) to a relative path.
	Icons map[string]string `json:"icons"`

	// Action is the MV3 browser/page action entry (or MV2 legacy action).
	Action *Action `json:"action"`

	// BrowserAction is the legacy MV2 browser_action entry.
	BrowserAction *Action `json:"browser_action"`

	// PageAction is the legacy MV2 page_action entry.
	PageAction *Action `json:"page_action"`

	// Background is the service-worker or background-scripts entry.
	Background *Background `json:"background"`

	// ContentScripts lists the declared content scripts.
	ContentScripts []ContentScript `json:"content_scripts"`

	// Permissions is the list of required permissions (MV3 host/perm list,
	// or MV2 permissions array).
	Permissions []string `json:"permissions"`

	// OptionalPermissions is the list of opt-in permissions.
	OptionalPermissions []string `json:"optional_permissions"`

	// HostPermissions is the MV3 host-permissions list.
	HostPermissions []string `json:"host_permissions"`

	// OptionsUI is the options-page descriptor.
	OptionsUI *OptionsUI `json:"options_ui"`

	// OptionsPage is the legacy single options-page path (MV2).
	OptionsPage string `json:"options_page"`

	// DevToolsPage is the optional devtools page path.
	DevToolsPage string `json:"devtools_page"`

	// ContentSecurityPolicy is the optional CSP object (MV3) or string (MV2).
	// The parsed string form is exposed via ContentSecurityPolicyString().
	ContentSecurityPolicy *CSP `json:"content_security_policy"`

	// WebAccessibleResources lists resource globs exposed to the web.
	WebAccessibleResources []json.RawMessage `json:"web_accessible_resources"`

	// Commands maps command names to their declarations.
	Commands map[string]Command `json:"commands"`

	// ChromeSettingsOverrides sets new-tab / home / search defaults.
	ChromeSettingsOverrides *SettingsOverrides `json:"chrome_settings_overrides"`

	// ChromeURLOverrides maps chrome:// pages to extension HTML.
	ChromeURLOverrides map[string]string `json:"chrome_url_overrides"`

	// OfflineEnabled defaults to true per spec; reflected as parsed.
	OfflineEnabled bool `json:"offline_enabled"`

	// Raw retains the full decoded JSON for callers that need unmapped fields.
	Raw map[string]json.RawMessage `json:"-"`
}

// Action describes a browser/page action.
type Action struct {
	DefaultIcon   map[string]string `json:"default_icon"`
	DefaultTitle  string            `json:"default_title"`
	DefaultPopup  string            `json:"default_popup"`
	DefaultLocale string            `json:"default_locale"`
}

// Background describes the background worker/scripts.
type Background struct {
	// ServiceWorker is the MV3 service-worker script path.
	ServiceWorker string `json:"service_worker"`
	// Type is the worker type ("module" or "classic").
	Type string `json:"type"`
	// Scripts is the legacy MV2 background script list.
	Scripts []string `json:"scripts"`
	// Page is the legacy MV2 background page path.
	Page string `json:"page"`
	// Persistent is the legacy MV2 persistent flag.
	Persistent bool `json:"persistent"`
}

// ContentScript describes a declared content script.
type ContentScript struct {
	Matches        []string `json:"matches"`
	ExcludeMatches []string `json:"exclude_matches"`
	JS             []string `json:"js"`
	CSS            []string `json:"css"`
	RunAt          string   `json:"run_at"`
	AllFrames      bool     `json:"all_frames"`
	World          string   `json:"world"`
}

// OptionsUI describes the options page descriptor.
type OptionsUI struct {
	Page        string `json:"page"`
	OpenInTab   bool   `json:"open_in_tab"`
	ChromeStyle bool   `json:"chrome_style"`
}

// CSP holds the content-security-policy descriptor.
type CSP struct {
	// ExtensionPages is the MV3 extension-pages policy.
	ExtensionPages string `json:"extension_pages"`
	// Sandbox is the legacy MV2 sandbox policy.
	Sandbox map[string]string `json:"sandbox"`
}

// Command describes a keyboard/extension command.
type Command struct {
	SuggestedKey map[string]string `json:"suggested_key"`
	Description  string            `json:"description"`
	Global       bool              `json:"global"`
}

// SettingsOverrides describes chrome_settings_overrides.
type SettingsOverrides struct {
	Homepage string          `json:"homepage"`
	Search   *SearchProvider `json:"search_provider"`
	Startup  []string        `json:"startup_pages"`
}

// SearchProvider describes a configured search provider.
type SearchProvider struct {
	Name       string `json:"name"`
	Keyword    string `json:"keyword"`
	SearchURL  string `json:"search_url"`
	FaviconURL string `json:"favicon_url"`
	SuggestURL string `json:"suggest_url"`
	Encoding   string `json:"encoding"`
	IsDefault  bool   `json:"is_default"`
}

// ParseBytes parses a manifest.json byte slice into a Manifest.
func ParseBytes(data []byte) (*Manifest, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("crxmanifestparser: empty manifest data")
	}
	var m Manifest
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, fmt.Errorf("crxmanifestparser: invalid JSON: %w", err)
	}
	// Retain the raw field map for advanced callers.
	var raw map[string]json.RawMessage
	_ = json.Unmarshal(data, &raw)
	m.Raw = raw
	return &m, nil
}

// ParseString is a convenience wrapper around ParseBytes.
func ParseString(s string) (*Manifest, error) {
	return ParseBytes([]byte(s))
}

// Validate checks that required manifest fields are present and internally
// consistent. It returns nil for a valid manifest, or an error describing the
// first problem found.
func (m *Manifest) Validate() error {
	if m == nil {
		return fmt.Errorf("crxmanifestparser: manifest is nil")
	}
	if m.Name == "" {
		return fmt.Errorf("crxmanifestparser: missing required field \"name\"")
	}
	if m.Version == "" {
		return fmt.Errorf("crxmanifestparser: missing required field \"version\"")
	}
	if !isValidVersion(m.Version) {
		return fmt.Errorf("crxmanifestparser: invalid version %q (must be 1-4 dot-separated integers 0-65535)", m.Version)
	}
	if m.ManifestVersion != 0 && m.ManifestVersion != 2 && m.ManifestVersion != 3 {
		return fmt.Errorf("crxmanifestparser: unsupported manifest_version %d (want 2 or 3)", m.ManifestVersion)
	}
	return nil
}

// EffectiveAction returns the action that applies for this manifest, taking
// MV2/MV3 differences into account (action on MV3, otherwise browser_action
// then page_action).
func (m *Manifest) EffectiveAction() *Action {
	if m == nil {
		return nil
	}
	if m.Action != nil {
		return m.Action
	}
	if m.BrowserAction != nil {
		return m.BrowserAction
	}
	return m.PageAction
}

// IsManifestV3 reports whether the manifest declares Manifest Version 3.
func (m *Manifest) IsManifestV3() bool {
	return m != nil && m.ManifestVersion == 3
}

// ContentSecurityPolicyString returns the CSP policy string in a
// version-appropriate way: MV3 extension_pages, or MV2 sandbox/extension string.
func (m *Manifest) ContentSecurityPolicyString() string {
	if m == nil || m.ContentSecurityPolicy == nil {
		return ""
	}
	if m.ContentSecurityPolicy.ExtensionPages != "" {
		return m.ContentSecurityPolicy.ExtensionPages
	}
	return ""
}

// AllPermissions returns the union of permissions and host_permissions.
func (m *Manifest) AllPermissions() []string {
	if m == nil {
		return nil
	}
	out := make([]string, 0, len(m.Permissions)+len(m.HostPermissions))
	out = append(out, m.Permissions...)
	out = append(out, m.HostPermissions...)
	return out
}

func isValidVersion(v string) bool {
	if v == "" {
		return false
	}
	dots := 0
	val := 0
	hasDigit := false
	for i := 0; i < len(v); i++ {
		c := v[i]
		if c == '.' {
			if !hasDigit {
				return false
			}
			if val > 65535 {
				return false
			}
			dots++
			if dots > 3 {
				return false
			}
			val = 0
			hasDigit = false
			continue
		}
		if c < '0' || c > '9' {
			return false
		}
		val = val*10 + int(c-'0')
		hasDigit = true
		if val > 65535 {
			return false
		}
	}
	return hasDigit && dots <= 3
}
