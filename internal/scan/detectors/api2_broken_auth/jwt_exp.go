package broken_auth

import (
	"context"

	"github.com/ahmedshamsddin/kashef/internal/detector"
	"github.com/ahmedshamsddin/kashef/internal/openapi"
	"github.com/ahmedshamsddin/kashef/internal/report"
)

func DetectNoJWTExpiryValidation(ctx context.Context, scanCtx *detector.Context, op openapi.Operation) []report.Finding {
	out := []report.Finding{}

	// Continue from here

	return out
}
