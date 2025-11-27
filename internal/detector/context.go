package detector

import (
	"net/http"
	"time"
)

type Context struct {
	BaseURL          string
	Client           *http.Client
	Headers          http.Header
	Token            string
	AllowWrite       bool
	Verbose          bool
	Timeout          time.Duration
	OOBServerFactory OOBServerFactory
}

type OOBServerFactory interface {
	Create() (OOBServer, error)
}

type OOBServer interface {
	Start() error
	Stop() error
	GenerateURL(identifier string) string
	CheckCallback(identifier string, timeout time.Duration) bool
}

func NewContext(baseURL string, client *http.Client, headers http.Header) *Context {
	return &Context{
		BaseURL: baseURL,
		Client:  client,
		Headers: headers.Clone(),
		Timeout: 15 * time.Second,
	}
}

func (c *Context) Clone() *Context {
	return &Context{
		BaseURL:          c.BaseURL,
		Client:           c.Client,
		Headers:          c.Headers.Clone(),
		Token:            c.Token,
		AllowWrite:       c.AllowWrite,
		Verbose:          c.Verbose,
		Timeout:          c.Timeout,
		OOBServerFactory: c.OOBServerFactory,
	}
}

func (c *Context) WithToken(token string) *Context {
	ctx := c.Clone()
	ctx.Token = token
	return ctx
}

func (c *Context) WithTimeout(timeout time.Duration) *Context {
	ctx := c.Clone()
	ctx.Timeout = timeout
	return ctx
}

func (c *Context) WithVerbose(verbose bool) *Context {
	ctx := c.Clone()
	ctx.Verbose = verbose
	return ctx
}

func (c *Context) WithAllowWrite(allow bool) *Context {
	ctx := c.Clone()
	ctx.AllowWrite = allow
	return ctx
}

func (c *Context) GetAuthHeader() string {
	// might be in cookies, check later
	if c.Token != "" {
		return "Bearer " + c.Token
	}
	return c.Headers.Get("Authorization")
}
