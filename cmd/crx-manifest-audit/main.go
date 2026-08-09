// Command crx-manifest-audit reads a Chromium extension manifest.json and
// prints a summary of the fields that matter for a permissions review:
// manifest version, validation result, the union of permissions and
// host_permissions, the content security policy, the background type and the
// content-script match patterns.
//
// It is a thin command-line front end over the crx-manifest-parser library and
// performs no network access. Reads a file path, or stdin when given "-".
//
//	crx-manifest-audit manifest.json
//	crx-manifest-audit -json manifest.json
//	cat manifest.json | crx-manifest-audit -
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	crx "github.com/theluckystrike/crx-manifest-parser"
)

// Report is the machine-readable form of the audit, emitted with -json.
type Report struct {
	Name            string   `json:"name"`
	Version         string   `json:"version"`
	ManifestVersion int      `json:"manifest_version"`
	IsMV3           bool     `json:"is_manifest_v3"`
	Valid           bool     `json:"valid"`
	ValidationError string   `json:"validation_error,omitempty"`
	Permissions     []string `json:"permissions"`
	HostPermissions []string `json:"host_permissions"`
	AllPermissions  []string `json:"all_permissions"`
	CSP             string   `json:"content_security_policy,omitempty"`
	BackgroundKind  string   `json:"background_kind,omitempty"`
	ContentScripts  []string `json:"content_script_matches,omitempty"`
	ActionPopup     string   `json:"action_popup,omitempty"`
}

func readInput(path string) ([]byte, error) {
	if path == "-" {
		return io.ReadAll(os.Stdin)
	}
	return os.ReadFile(path)
}

func backgroundKind(m *crx.Manifest) string {
	if m.Background == nil {
		return ""
	}
	if m.Background.ServiceWorker != "" {
		return "service_worker: " + m.Background.ServiceWorker
	}
	if len(m.Background.Scripts) > 0 {
		return "scripts: " + strings.Join(m.Background.Scripts, ", ")
	}
	return ""
}

func contentScriptMatches(m *crx.Manifest) []string {
	out := []string{}
	for _, cs := range m.ContentScripts {
		out = append(out, cs.Matches...)
	}
	return out
}

// Build assembles a Report from an already-parsed manifest.
func Build(m *crx.Manifest) Report {
	r := Report{
		Name:            m.Name,
		Version:         m.Version,
		ManifestVersion: m.ManifestVersion,
		IsMV3:           m.IsManifestV3(),
		Permissions:     m.Permissions,
		HostPermissions: m.HostPermissions,
		AllPermissions:  m.AllPermissions(),
		CSP:             m.ContentSecurityPolicyString(),
		BackgroundKind:  backgroundKind(m),
		ContentScripts:  contentScriptMatches(m),
	}
	if r.Permissions == nil {
		r.Permissions = []string{}
	}
	if r.HostPermissions == nil {
		r.HostPermissions = []string{}
	}
	if r.AllPermissions == nil {
		r.AllPermissions = []string{}
	}
	if err := m.Validate(); err != nil {
		r.ValidationError = err.Error()
	} else {
		r.Valid = true
	}
	if a := m.EffectiveAction(); a != nil {
		r.ActionPopup = a.DefaultPopup
	}
	return r
}

func writeLine(w io.Writer, k, v string) {
	if v != "" {
		fmt.Fprintf(w, "%-22s %s\n", k+":", v)
	}
}

// Text renders the human-readable report.
func Text(w io.Writer, r Report) {
	writeLine(w, "name", r.Name)
	writeLine(w, "version", r.Version)
	writeLine(w, "manifest_version", fmt.Sprintf("%d", r.ManifestVersion))
	writeLine(w, "manifest v3", fmt.Sprintf("%t", r.IsMV3))
	if r.Valid {
		writeLine(w, "valid", "yes")
	} else {
		writeLine(w, "valid", "no - "+r.ValidationError)
	}
	writeLine(w, "permissions", strings.Join(r.Permissions, ", "))
	writeLine(w, "host_permissions", strings.Join(r.HostPermissions, ", "))
	writeLine(w, "permission count", fmt.Sprintf("%d", len(r.AllPermissions)))
	writeLine(w, "background", r.BackgroundKind)
	writeLine(w, "content_scripts", strings.Join(r.ContentScripts, ", "))
	writeLine(w, "action popup", r.ActionPopup)
	writeLine(w, "csp", r.CSP)
}

func run(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("crx-manifest-audit", flag.ContinueOnError)
	fs.SetOutput(stderr)
	asJSON := fs.Bool("json", false, "emit the report as JSON")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 1 {
		fmt.Fprintln(stderr, "usage: crx-manifest-audit [-json] <manifest.json|->")
		return 2
	}
	data, err := readInput(fs.Arg(0))
	if err != nil {
		fmt.Fprintln(stderr, "read:", err)
		return 1
	}
	m, err := crx.ParseBytes(data)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	rep := Build(m)
	if *asJSON {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(rep); err != nil {
			fmt.Fprintln(stderr, err)
			return 1
		}
	} else {
		Text(stdout, rep)
	}
	if !rep.Valid {
		return 1
	}
	return 0
}

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}
