package detector

import (
	"context"
	"fmt"
	"sync"

	"github.com/ahmedshamsddin/kashef/internal/openapi"
	"github.com/ahmedshamsddin/kashef/internal/report"
)

type Registry struct {
	mu        sync.RWMutex
	detectors []Detector
}

var globalRegistry = &Registry{
	detectors: make([]Detector, 0),
}

func Register(detector Detector) {
	globalRegistry.Register(detector)
}

func (r *Registry) Register(detector Detector) {
	r.mu.Lock()
	defer r.mu.Unlock()

	info := detector.Info()

	for _, existing := range r.detectors {
		if existing.Info().ID == info.ID {
			panic(fmt.Sprintf("detector with ID %s is already registered", info.ID))
		}
	}

	r.detectors = append(r.detectors, detector)
}

func (r *Registry) List() []Detector {
	r.mu.RLock()
	defer r.mu.RUnlock()

	result := make([]Detector, len(r.detectors))
	copy(result, r.detectors)
	return result
}

func (r *Registry) Get(id string) (Detector, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	for _, d := range r.detectors {
		if d.Info().ID == id {
			return d, true
		}
	}
	return nil, false
}

func (r *Registry) RunAll(ctx context.Context, scanCtx *Context, op openapi.Operation) []report.Finding {
	r.mu.RLock()
	detectors := make([]Detector, len(r.detectors))
	copy(detectors, r.detectors)
	r.mu.Unlock()

	var findings []report.Finding

	for _, detector := range detectors {
		info := detector.Info()

		if !info.AppliesTo.ShouldRun(op) {
			continue
		}

		if info.RequiresAuth && !op.RequiresAuth {
			continue
		}

		if info.RequiresWrite && !scanCtx.AllowWrite {
			if scanCtx.Verbose {
				fmt.Printf("[%s] skipped (requires --allow-write)\n", info.ID)
			}
			continue
		}

		if scanCtx.Verbose {
			fmt.Printf("[%s] running on %s %s\n", info.ID, op.Method, op.Path)
		}

		detectorFindings := detector.Detect(ctx, scanCtx, op)

		if len(detectorFindings) > 0 && scanCtx.Verbose {
			fmt.Printf("[%s] found %d issue(s)\n", info.ID, len(detectorFindings))
		}

		findings = append(findings, detectorFindings...)
	}

	return findings
}

func List() []Detector {
	return globalRegistry.List()
}

func Get(id string) (Detector, bool) {
	return globalRegistry.Get(id)
}

func RunAll(ctx context.Context, scanCtx *Context, op openapi.Operation) []report.Finding {
	return globalRegistry.RunAll(ctx, scanCtx, op)
}

// Count returns the number of registered detectors
func Count() int {
	return len(globalRegistry.List())
}

// Clear removes all registered detectors (useful for testing)
func Clear() {
	globalRegistry.mu.Lock()
	defer globalRegistry.mu.Unlock()
	globalRegistry.detectors = make([]Detector, 0)
}
