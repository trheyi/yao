package shared

import (
	"bytes"
	"errors"
	"io/fs"
	"os"
	"path"
	"strings"
)

const systemToolsMarker = "<!-- Yao System Tools (auto-injected) -->"

// writerFS is the minimal filesystem interface needed by the injection helpers.
// workspace.FS satisfies this interface.
type writerFS interface {
	ReadFile(name string) ([]byte, error)
	WriteFile(name string, data []byte, perm os.FileMode) error
	MkdirAll(name string, perm os.FileMode) error
}

// InjectSystemSkills copies SKILL files from an embed.FS into the workspace.
// The skills parameter should be an embed.FS produced by `//go:embed skills`,
// where each file has a path like "skills/yao-web/SKILL.md". This function
// strips the "skills/" prefix and writes files into targetDir (e.g. ".claude/skills").
func InjectSystemSkills(ws writerFS, skills fs.FS, targetDir string) error {
	return fs.WalkDir(skills, "skills", func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}

		rel := strings.TrimPrefix(p, "skills/")
		dst := path.Join(targetDir, rel)

		data, err := fs.ReadFile(skills, p)
		if err != nil {
			return err
		}

		dir := path.Dir(dst)
		if err := ws.MkdirAll(dir, 0755); err != nil {
			return err
		}
		return ws.WriteFile(dst, data, 0644)
	})
}

// AppendSystemPrompt appends content to a file in the workspace with an
// idempotent marker. If the marker already exists the call is a no-op.
// If the file does not exist it is created with just the marker + content.
func AppendSystemPrompt(ws writerFS, filename string, content []byte) error {
	existing, err := ws.ReadFile(filename)
	if err != nil {
		if !errors.Is(err, fs.ErrNotExist) {
			return err
		}
		header := []byte(systemToolsMarker + "\n\n")
		return ws.WriteFile(filename, append(header, content...), 0644)
	}

	if bytes.Contains(existing, []byte(systemToolsMarker)) {
		return nil
	}

	separator := []byte("\n\n---\n\n" + systemToolsMarker + "\n\n")
	merged := append(existing, append(separator, content...)...)
	return ws.WriteFile(filename, merged, 0644)
}
