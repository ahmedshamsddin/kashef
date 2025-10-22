package openapi

import (
	"context"
	"errors"
	"net/url"
	"strings"

	"github.com/getkin/kin-openapi/openapi3"
)

type Spec struct {
	Doc    *openapi3.T
	Server string
}

func Load(ctx context.Context, pathOrURL string) (*Spec, error) {
	ldr := &openapi3.Loader{IsExternalRefsAllowed: true}
	var doc *openapi3.T
	u, _ := url.Parse(pathOrURL)
	var err error
	if u != nil && (u.Scheme == "http" || u.Scheme == "https") {
		doc, err = ldr.LoadFromURI(u)
	} else {
		doc, err = ldr.LoadFromFile(pathOrURL)
	}
	if err != nil {
		return nil, err
	}
	_ = doc.Validate(ctx) // don’t fail strictly for MVP

	srv := ""
	if len(doc.Servers) > 0 {
		srv = strings.TrimRight(doc.Servers[0].URL, "/")
	}
	if srv == "" {
		return nil, errors.New("no servers[0].url in spec")
	}
	return &Spec{Doc: doc, Server: srv}, nil
}
