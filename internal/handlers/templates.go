package handlers

import (
	"encoding/json"
	"forum/internal/entity"
	"forum/web"
	"html/template"
	"io/fs"
	"log"
	"path/filepath"
	"strings"
)

type Models struct {
	Posts          []entity.PostView
	Post           entity.PostView
	Tags           []entity.TagEntity
	Notifications  []entity.Notification
	Requests       []entity.Request
	Reports        []entity.Report
	Users          []entity.UserEntity
	DashboardStats entity.DashboardStats
}

type templateData struct {
	Models             Models
	Username           string
	UserRole           string
	IsAuthenticated    bool
	NotificationsCount int
}

type errData struct {
	ErrCode int
	ErrMsg  string
}

var fm = template.FuncMap{
	"low":  strings.ToLower,
	"cap":  strings.Title,
	"json": toJSON,
}

func toJSON(v interface{}) string {
	a, err := json.Marshal(v)
	if err != nil {
		log.Println("Error marshalling to JSON:", err)
		return "[]"
	}
	return string(a)
}

// newTemplateCache initializes all templates and stores them in map
// in which key is the name of the template and value is parsed template
func newTemplateCache() (map[string]*template.Template, error) {
	cache := map[string]*template.Template{}

	pages, err := fs.Glob(web.Files, "html/pages/*.html")
	if err != nil {
		return nil, err
	}

	for _, page := range pages {
		name := filepath.Base(page)

		files := []string{
			"html/base.html",
			"html/partials/nav.html",
			"html/partials/topics.html",
			"html/partials/userbar.html",
			page,
		}

		ts, err := template.New("").Funcs(fm).ParseFS(web.Files, files...)
		if err != nil {
			return nil, err
		}

		cache[name] = ts
	}

	return cache, nil
}
