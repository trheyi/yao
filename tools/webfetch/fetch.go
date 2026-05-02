package webfetch

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"path"
	"strings"
	"time"
)

const (
	directTimeout     = 15 * time.Second
	brightdataTimeout = 90 * time.Second
	headTimeout       = 5 * time.Second
	maxBodySize       = 10 * 1024 * 1024 // 10 MB
	minDirectBody     = 500
	minMarkdownBody   = 100
	botUserAgent      = "Mozilla/5.0 (compatible; YaoBot/1.0; +https://yao.run)"
	browserUserAgent  = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
)

type fetchResult struct {
	Body        []byte
	StatusCode  int
	ContentType string
}

func directFetch(targetURL string, useBot bool) (*fetchResult, error) {
	client := &http.Client{Timeout: directTimeout}
	req, err := http.NewRequest(http.MethodGet, targetURL, nil)
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}

	if useBot {
		req.Header.Set("User-Agent", botUserAgent)
		req.Header.Set("Accept", "text/markdown,text/plain,text/html,*/*;q=0.8")
	} else {
		req.Header.Set("User-Agent", browserUserAgent)
		req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("http get: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBodySize))
	if err != nil {
		return nil, fmt.Errorf("read body: %w", err)
	}

	return &fetchResult{
		Body:        body,
		StatusCode:  resp.StatusCode,
		ContentType: resp.Header.Get("Content-Type"),
	}, nil
}

func brightdataFetch(targetURL, apiKey, zone string) ([]byte, error) {
	payload, _ := json.Marshal(map[string]string{
		"zone":   zone,
		"url":    targetURL,
		"format": "raw",
	})

	client := &http.Client{Timeout: brightdataTimeout}
	req, err := http.NewRequest(http.MethodPost, "https://api.brightdata.com/request", bytes.NewReader(payload))
	if err != nil {
		return nil, fmt.Errorf("build brightdata request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+apiKey)
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("brightdata request: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBodySize))
	if err != nil {
		return nil, fmt.Errorf("read brightdata response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("brightdata HTTP %d: %s", resp.StatusCode, truncate(string(body), 200))
	}
	return body, nil
}

func headCheck(url string) (int, error) {
	client := &http.Client{Timeout: headTimeout}
	req, err := http.NewRequest(http.MethodHead, url, nil)
	if err != nil {
		return 0, fmt.Errorf("build head request: %w", err)
	}
	req.Header.Set("User-Agent", botUserAgent)
	resp, err := client.Do(req)
	if err != nil {
		return 0, fmt.Errorf("head request: %w", err)
	}
	resp.Body.Close()
	return resp.StatusCode, nil
}

// fetchHTML tries direct GET first, falls back to Brightdata.
func fetchHTML(cfg *fetchConfig, targetURL string) *FetchResponse {
	res, err := directFetch(targetURL, false)
	if err == nil && res.StatusCode == 200 && len(res.Body) >= minDirectBody {
		htmlStr := string(res.Body)
		return &FetchResponse{
			URL:     targetURL,
			Title:   ExtractTitle(htmlStr),
			Content: ExtractContent(htmlStr),
			Format:  "html",
		}
	}

	if cfg.BrightdataKey != "" {
		body, err := brightdataFetch(targetURL, cfg.BrightdataKey, cfg.BrightdataZone)
		if err == nil {
			htmlStr := string(body)
			return &FetchResponse{
				URL:     targetURL,
				Title:   ExtractTitle(htmlStr),
				Content: ExtractContent(htmlStr),
				Format:  "html",
			}
		}
	}

	return &FetchResponse{
		URL:     targetURL,
		Content: fmt.Sprintf("Failed to fetch %s", targetURL),
		Format:  "html",
	}
}

// fetchMarkdown tries .md probing, then HTML -> markdown conversion.
func fetchMarkdown(cfg *fetchConfig, targetURL string) *FetchResponse {
	lower := strings.ToLower(targetURL)
	ext := strings.ToLower(path.Ext(strings.TrimSuffix(lower, "/")))

	// Already a .md file
	if ext == ".md" || ext == ".mdx" {
		res, err := directFetch(targetURL, true)
		if err == nil && res.StatusCode == 200 && len(res.Body) >= minMarkdownBody {
			return &FetchResponse{
				URL:     targetURL,
				Content: string(res.Body),
				Format:  "markdown",
			}
		}
	}

	// Probe for .md version
	mdURL := buildMdURL(targetURL)
	if mdURL != "" {
		code, err := headCheck(mdURL)
		if err == nil && code == 200 {
			res, err := directFetch(mdURL, true)
			if err == nil && res.StatusCode == 200 && len(res.Body) >= minMarkdownBody {
				return &FetchResponse{
					URL:     targetURL,
					Content: string(res.Body),
					Format:  "markdown",
				}
			}
		}
	}

	// Fallback: fetch HTML and convert
	htmlRes := fetchRawHTML(cfg, targetURL)
	if htmlRes == nil {
		return &FetchResponse{
			URL:     targetURL,
			Content: fmt.Sprintf("Failed to fetch %s", targetURL),
			Format:  "markdown",
		}
	}

	htmlStr := string(htmlRes)
	md := HtmlToMarkdown(htmlStr)
	title := ExtractTitle(htmlStr)
	if title != "" {
		md = "# " + title + "\n\n" + md
	}

	return &FetchResponse{
		URL:     targetURL,
		Title:   title,
		Content: md,
		Format:  "markdown",
	}
}

// fetchRawHTML fetches HTML with direct -> brightdata fallback.
func fetchRawHTML(cfg *fetchConfig, targetURL string) []byte {
	res, err := directFetch(targetURL, false)
	if err == nil && res.StatusCode == 200 && len(res.Body) >= minDirectBody {
		return res.Body
	}

	if cfg.BrightdataKey != "" {
		body, err := brightdataFetch(targetURL, cfg.BrightdataKey, cfg.BrightdataZone)
		if err == nil {
			return body
		}
	}
	return nil
}

func buildMdURL(u string) string {
	ext := strings.ToLower(path.Ext(strings.TrimSuffix(u, "/")))
	if ext == ".md" || ext == ".mdx" {
		return ""
	}
	trimmed := strings.TrimSuffix(u, "/")
	return trimmed + ".md"
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
