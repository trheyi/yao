package local

import (
	"fmt"
	"io"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/yaoapp/gou/process"
	"github.com/yaoapp/yao/sui/core"
	"golang.org/x/text/language"
)

// Assets get the assets treelist
func (tmpl *Template) Assets() []string {
	return nil
}

// GetRoot get the root path
func (tmpl *Template) GetRoot() string {
	return tmpl.Root
}

// Reload the template
func (tmpl *Template) Reload() error {
	newTmpl, err := tmpl.local.getTemplateFrom(tmpl.Root)
	if err != nil {
		return err
	}
	*tmpl = *newTmpl
	return nil
}

// ExecBeforeBuildScripts execute the before build scripts
func (tmpl *Template) ExecBeforeBuildScripts() []core.TemplateScirptResult {
	if tmpl.Scripts == nil || len(tmpl.Scripts.BeforeBuild) == 0 {
		return nil
	}
	return tmpl.ExecScripts(tmpl.Scripts.BeforeBuild)
}

// ExecAfterBuildScripts execute the after build scripts
func (tmpl *Template) ExecAfterBuildScripts() []core.TemplateScirptResult {
	if tmpl.Scripts == nil || len(tmpl.Scripts.AfterBuild) == 0 {
		return nil
	}
	return tmpl.ExecScripts(tmpl.Scripts.AfterBuild)
}

// ExecScripts execute the scripts
func (tmpl *Template) ExecScripts(scripts []*core.TemplateScript) []core.TemplateScirptResult {
	results := []core.TemplateScirptResult{}
	for _, script := range scripts {
		switch script.Type {
		case "command":
			results = append(results, tmpl.execCommand(script))
		case "process":
			results = append(results, tmpl.execProcess(script))
		}
	}
	return results
}

func (tmpl *Template) execProcess(script *core.TemplateScript) core.TemplateScirptResult {
	result := core.TemplateScirptResult{Script: script, Message: "", Error: nil}
	name := script.Content
	p, err := process.Of(name, tmpl.Root)
	if err != nil {
		result.Error = err
		return result
	}

	output, err := p.Exec()
	result.Error = err
	result.Message = fmt.Sprintf("%v", output)
	return result
}

func (tmpl *Template) execCommand(script *core.TemplateScript) core.TemplateScirptResult {
	result := core.TemplateScirptResult{Script: script, Message: "", Error: nil}
	root := filepath.Join(tmpl.local.fs.Root(), tmpl.Root)

	// Parse the command
	cmd := strings.Split(script.Content, " ")
	if len(cmd) == 0 {
		result.Error = fmt.Errorf("Command is empty")
		return result
	}

	execCmd := exec.Command(cmd[0], cmd[1:]...)
	execCmd.Dir = root
	output, err := execCmd.CombinedOutput()
	result.Error = err
	result.Message = string(output)
	return result
}

// Locales get the global locales
func (tmpl *Template) Locales() []core.SelectOption {
	if tmpl.locales != nil {
		return tmpl.locales
	}

	supportLocales := []core.SelectOption{}
	path := filepath.Join(tmpl.Root, "__locales")
	if !tmpl.local.fs.IsDir(path) {
		return nil
	}

	dirs, err := tmpl.local.fs.ReadDir(path, false)
	if err != nil {
		return nil
	}

	for _, dir := range dirs {
		locale := filepath.Base(dir)
		label := language.Make(locale).String()
		supportLocales = append(supportLocales, core.SelectOption{
			Value: locale,
			Label: label,
		})
	}

	tmpl.locales = supportLocales
	return tmpl.locales
}

// Themes get the global themes
func (tmpl *Template) Themes() []core.SelectOption {
	return tmpl.Template.Themes
}

// MediaSearch search the asset
func (tmpl *Template) MediaSearch(query url.Values, page int, pageSize int) (core.MediaSearchResult, error) {
	res := core.MediaSearchResult{Data: []core.Media{}, Page: page, PageSize: pageSize}
	keyword := query.Get("keyword")
	types := query["types"]
	if types == nil {
		types = []string{"image", "video", "audio"}
	}
	exts := tmpl.mediaExts(types)
	path := filepath.Join(tmpl.Root, "__assets", "upload")
	files, total, pagecnt, err := tmpl.local.fs.List(path, exts, page, pageSize, func(s string) bool {
		if keyword == "" {
			return true
		}
		return strings.Contains(s, keyword)
	})

	if err != nil {
		return res, err
	}

	for _, file := range files {

		file = strings.TrimPrefix(file, filepath.Join(tmpl.Root, "__assets", "upload"))
		res.Data = append(res.Data, core.Media{
			ID:     file,
			URL:    filepath.Join("@assets", "upload", file),
			Thumb:  filepath.Join("@assets", "upload", file),
			Type:   tmpl.mediaType(file),
			Width:  100,
			Height: 100,
		})
	}

	res.Next = page + 1
	if (page+1)*pageSize >= total {
		res.Next = 0
	}

	res.Prev = page - 1
	if page == 1 {
		res.Prev = 0
	}

	res.Total = total
	res.PageCount = pagecnt

	return res, nil
}

func (tmpl *Template) mediaExts(types []string) []string {
	exts := []string{}
	for _, typ := range types {
		switch typ {

		case "image":
			exts = append(exts, []string{".jpg", ".jpeg", ".png"}...)
			break

		case "video":
			exts = append(exts, []string{".mp4"}...)
			break

		case "audio":
			exts = append(exts, []string{".mp3"}...)
			break
		}
	}

	return exts
}

func (tmpl *Template) mediaType(file string) string {
	ext := strings.ToLower(filepath.Ext(file))
	switch ext {

	case ".jpg":
		return "image"

	case ".jpeg":
		return "image"

	case ".png":
		return "image"

	case ".gif":
		return "image"

	case ".bmp":
		return "image"

	case ".mp4":
		return "video"

	case ".mp3":
		return "audio"
	}

	return "file"
}

// AssetUpload upload the asset
func (tmpl *Template) AssetUpload(reader io.Reader, name string) (string, error) {

	fingerprint := strings.ToUpper(uuid.NewString())
	dir := strings.Join([]string{string(os.PathSeparator), time.Now().Format("20060102")}, "")
	ext := filepath.Ext(name)
	file := filepath.Join(tmpl.Root, "__assets", "upload", dir, fmt.Sprintf("%s%s", fingerprint, ext))
	_, err := tmpl.local.fs.Write(file, reader, 0644)
	if err != nil {
		return "", err
	}
	return filepath.Join("upload", dir, fmt.Sprintf("%s%s", fingerprint, ext)), nil
}

// Asset get the asset
func (tmpl *Template) Asset(file string, width, height uint) (*core.Asset, error) {

	file = filepath.Join(tmpl.Root, "__assets", file)
	if exist, _ := tmpl.local.fs.Exists(file); exist {

		if width > 0 || height > 0 {
			return tmpl.assetThumb(file, width, height)
		}

		content, err := tmpl.local.fs.ReadFile(file)
		if err != nil {
			return nil, err
		}

		typ := "text/plain"
		switch filepath.Ext(file) {
		case ".css":
			typ = "text/css; charset=utf-8"
			break

		case ".js":
			typ = "application/javascript; charset=utf-8"
			break

		case ".ts":
			typ = "application/javascript; charset=utf-8"
			break

		case ".json":
			typ = "application/json; charset=utf-8"
			break

		case ".html":
			typ = "text/html; charset=utf-8"
			break

		default:
			typ, err = tmpl.local.fs.MimeType(file)
			if err != nil {
				return nil, err
			}
		}

		return &core.Asset{Type: typ, Content: content}, nil
	}

	return nil, fmt.Errorf("Asset %s not found", file)
}

func (tmpl *Template) assetThumb(file string, width, height uint) (*core.Asset, error) {

	cacheFile := filepath.Join(tmpl.Root, "__assets", ".cache", fmt.Sprintf("%dx%d", width, height), file)
	exist, _ := tmpl.local.fs.Exists(cacheFile)
	if !exist {
		err := tmpl.local.fs.Resize(file, cacheFile, width, height)
		if err != nil {
			return nil, err
		}
	}

	typ, err := tmpl.local.fs.MimeType(file)
	if err != nil {
		return nil, err
	}

	content, err := tmpl.local.fs.ReadFile(cacheFile)
	if err != nil {
		return nil, err
	}
	return &core.Asset{Type: typ, Content: content}, nil
}
