package detector

import (
	"context"

	"github.com/ahmedshamsddin/kashef/internal/openapi"
	"github.com/ahmedshamsddin/kashef/internal/report"
)

type Detector interface {
	Info() DetectorInfo
	Detect(ctx context.Context, scanCtx *Context, op openapi.Operation) []report.Finding
}

type DetectorInfo struct {
	ID            string
	Name          string
	Description   string
	OWASP         string
	Category      string
	RequiresAuth  bool
	RequiresWrite bool
	AppliesTo     AppliesTo
}

type AppliesTo struct {
	Methods         []string
	OperationsTypes []string
	IsInstance      *bool
	IsCollection    *bool
}

func (a AppliesTo) ShouldRun(op openapi.Operation) bool {
	if len(a.Methods) > 0 {
		found := false
		for _, method := range a.Methods {
			if method == op.Method {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}

	if len(a.OperationsTypes) > 0 {
		found := false
		for _, opType := range a.OperationsTypes {
			if opType == op.OperationType {
				found = true
				break
			}
		}

		if !found {
			return false
		}
	}

	if a.IsInstance != nil {
		if *a.IsInstance != op.IsInstance {
			return false
		}
	}

	if a.IsCollection != nil {
		if *a.IsCollection != op.IsCollection {
			return false
		}
	}

	return true
}

func OnlyMethods(methods ...string) AppliesTo {
	return AppliesTo{Methods: methods}
}

func OnlyInstances() AppliesTo {
	t := true
	return AppliesTo{IsInstance: &t}
}

func OnlyCollections() AppliesTo {
	t := true
	return AppliesTo{IsCollection: &t}
}

func OnlyOperationTypes(types ...string) AppliesTo {
	return AppliesTo{OperationsTypes: types}
}
