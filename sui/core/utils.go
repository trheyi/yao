package core

import (
	"bytes"
	"fmt"
	"strings"

	"github.com/PuerkitoBio/goquery"
	"golang.org/x/net/html"
)

// NewDocument create a new document
func NewDocument(htmlContent []byte) (*goquery.Document, error) {
	docNode, err := html.Parse(bytes.NewReader(htmlContent))
	if err != nil {
		return nil, err
	}
	return goquery.NewDocumentFromNode(docNode), nil
}

// NewDocumentString create a new document
func NewDocumentString(htmlContent string) (*goquery.Document, error) {
	docNode, err := html.Parse(strings.NewReader(htmlContent))
	if err != nil {
		return nil, err
	}
	return goquery.NewDocumentFromNode(docNode), nil
}

// NewDocumentStringWithWrapper create a new document with a wrapper
func NewDocumentStringWithWrapper(htmlContent string) (*goquery.Document, error) {
	doc, err := NewDocumentString(htmlContent)
	if err != nil {
		return nil, err
	}

	// Check if the doc has root element add a div wrapper
	nodes := doc.Find("Body *").Nodes
	if len(nodes) == 1 {
		sel := goquery.NewDocumentFromNode(nodes[0])
		if _, has := sel.Attr("is"); has {
			doc, err := NewDocumentString(fmt.Sprintf("<div>\n%s\n</div>", htmlContent))
			if err != nil {
				return nil, err
			}
			return doc, nil
		}
	}
	return doc, nil
}

// Namespace convert the name to namespace
func Namespace(name string, idx int) string {
	name = strings.ReplaceAll(name, "/", "_")
	name = strings.ReplaceAll(name, "[", "_")
	name = strings.ReplaceAll(name, "]", "_")
	return fmt.Sprintf("__page_%s_%d", name, idx)
}

// ComponentName convert the name to component name
func ComponentName(name string) string {
	name = strings.ReplaceAll(name, "/", "_")
	name = strings.ReplaceAll(name, "[", "_")
	name = strings.ReplaceAll(name, "]", "_")
	return fmt.Sprintf("__component_%s", name)
}
