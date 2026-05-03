package shared

import (
	"io/fs"
	"os"
	"path/filepath"
	"testing"
	"testing/fstest"
)

func TestInjectSystemSkills_CopiesAllFiles(t *testing.T) {
	dir := t.TempDir()
	ws := newDirFS(dir)

	skills := fstest.MapFS{
		"skills/yao-web/SKILL.md":     {Data: []byte("web skill")},
		"skills/yao-process/SKILL.md": {Data: []byte("process skill")},
		"skills/yao-doc/SKILL.md":     {Data: []byte("doc skill")},
	}

	if err := InjectSystemSkills(ws, skills, ".claude/skills"); err != nil {
		t.Fatalf("InjectSystemSkills: %v", err)
	}

	for _, tc := range []struct {
		path string
		want string
	}{
		{".claude/skills/yao-web/SKILL.md", "web skill"},
		{".claude/skills/yao-process/SKILL.md", "process skill"},
		{".claude/skills/yao-doc/SKILL.md", "doc skill"},
	} {
		data, err := os.ReadFile(filepath.Join(dir, tc.path))
		if err != nil {
			t.Errorf("ReadFile(%s): %v", tc.path, err)
			continue
		}
		if string(data) != tc.want {
			t.Errorf("%s = %q, want %q", tc.path, data, tc.want)
		}
	}
}

func TestAppendSystemPrompt_CreatesNewFile(t *testing.T) {
	dir := t.TempDir()
	ws := newDirFS(dir)

	content := []byte("## Yao System Tools\ntai tool ...")
	if err := AppendSystemPrompt(ws, "CLAUDE.md", content); err != nil {
		t.Fatalf("AppendSystemPrompt: %v", err)
	}

	data, err := os.ReadFile(filepath.Join(dir, "CLAUDE.md"))
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if got := string(data); got == "" {
		t.Fatal("file should not be empty")
	}
	assertContains(t, string(data), systemToolsMarker)
	assertContains(t, string(data), "Yao System Tools")
}

func TestAppendSystemPrompt_AppendsToExisting(t *testing.T) {
	dir := t.TempDir()
	ws := newDirFS(dir)

	existing := []byte("# My Project\n\nExisting content.\n")
	if err := os.WriteFile(filepath.Join(dir, "CLAUDE.md"), existing, 0644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	content := []byte("## System Tools\n")
	if err := AppendSystemPrompt(ws, "CLAUDE.md", content); err != nil {
		t.Fatalf("AppendSystemPrompt: %v", err)
	}

	data, err := os.ReadFile(filepath.Join(dir, "CLAUDE.md"))
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	got := string(data)
	assertContains(t, got, "My Project")
	assertContains(t, got, systemToolsMarker)
	assertContains(t, got, "System Tools")
}

func TestAppendSystemPrompt_Idempotent(t *testing.T) {
	dir := t.TempDir()
	ws := newDirFS(dir)

	content := []byte("## Yao System Tools\n")

	if err := AppendSystemPrompt(ws, "AGENTS.md", content); err != nil {
		t.Fatalf("first call: %v", err)
	}
	first, _ := os.ReadFile(filepath.Join(dir, "AGENTS.md"))

	if err := AppendSystemPrompt(ws, "AGENTS.md", content); err != nil {
		t.Fatalf("second call: %v", err)
	}
	second, _ := os.ReadFile(filepath.Join(dir, "AGENTS.md"))

	if string(first) != string(second) {
		t.Errorf("second call modified the file (not idempotent):\n--- first ---\n%s\n--- second ---\n%s", first, second)
	}
}

func assertContains(t *testing.T, s, sub string) {
	t.Helper()
	if len(s) < len(sub) {
		t.Errorf("string does not contain %q", sub)
		return
	}
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return
		}
	}
	t.Errorf("string does not contain %q:\n%s", sub, s)
}

// dirFS is a minimal workspace.FS backed by a real directory (for testing).
type dirFS struct {
	root string
}

func newDirFS(root string) *dirFS { return &dirFS{root: root} }

func (d *dirFS) Open(name string) (fs.File, error) {
	return os.Open(filepath.Join(d.root, name))
}

func (d *dirFS) ReadFile(name string) ([]byte, error) {
	data, err := os.ReadFile(filepath.Join(d.root, name))
	if err != nil {
		return nil, err
	}
	return data, nil
}

func (d *dirFS) WriteFile(name string, data []byte, perm os.FileMode) error {
	return os.WriteFile(filepath.Join(d.root, name), data, perm)
}

func (d *dirFS) MkdirAll(name string, perm os.FileMode) error {
	return os.MkdirAll(filepath.Join(d.root, name), perm)
}
