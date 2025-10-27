package broken_auth

import (
	"context"

	"github.com/ahmedshamsddin/kashef/internal/openapi"
	"github.com/ahmedshamsddin/kashef/internal/report"
)

func DetectNoJWTExpiryValidation(ctx context.Context, sc Context, op openapi.Operation) []report.Finding {
	out := []report.Finding{}

	// Continue from here

	return out
}
