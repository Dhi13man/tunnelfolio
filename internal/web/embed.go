package web

import (
	"embed"
	"errors"
)

//go:embed index.html assets/*
var files embed.FS

func Index() ([]byte, error) { return files.ReadFile("index.html") }

func Asset(name string) ([]byte, string, error) {
	switch name {
	case "app.css":
		data, err := files.ReadFile("assets/app.css")
		return data, "text/css; charset=utf-8", err
	case "api.js", "app.js", "connection.js", "detail.js", "import.js", "library.js", "state.js":
		data, err := files.ReadFile("assets/" + name)
		return data, "text/javascript; charset=utf-8", err
	default:
		return nil, "", errors.New("asset not found")
	}
}
