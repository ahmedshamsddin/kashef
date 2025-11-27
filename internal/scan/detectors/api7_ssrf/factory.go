package api7ssrf

import (
	"context"
	"time"

	"github.com/ahmedshamsddin/kashef/internal/detector"
)

type SimpleOOBFactory struct{}

func NewOOBFactory() detector.OOBServerFactory {
	return &SimpleOOBFactory{}
}

func (f *SimpleOOBFactory) Create() (detector.OOBServer, error) {
	return &OOBServerAdapter{server: newSimpleOOBServer()}, nil
}

// OOBServerAdapter adapts SimpleOOBServer to detector.OOBServer interface
type OOBServerAdapter struct {
	server *SimpleOOBServer
}

func (a *OOBServerAdapter) Start() error {
	return a.server.Start(context.Background())
}

func (a *OOBServerAdapter) Stop() error {
	return a.server.Stop()
}

func (a *OOBServerAdapter) GenerateURL(identifier string) string {
	return a.server.GenerateURL(identifier)
}

func (a *OOBServerAdapter) CheckCallback(identifier string, timeout time.Duration) bool {
	return a.server.CheckCallback(identifier, timeout)
}
