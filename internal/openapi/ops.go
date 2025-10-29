package openapi

import (
	"encoding/json"
	"strings"

	"github.com/getkin/kin-openapi/openapi3"
)

type Operation struct {
	Method             string
	Path               string
	PathParameterNames []string
	IsCollection       bool
	IsInstance         bool
	OperationType      string
	RequiresAuth       bool
	Consumes           []string
	Produces           []string
	RequestExamples    map[string][]byte
	ResponseExamples   map[string][]byte

	Raw *openapi3.Operation
}

func (s *Spec) Operations() []Operation {
	var operations []Operation

	if s == nil || s.Doc == nil || s.Doc.Paths == nil {
		return operations
	}

	var rootRequiresAuth bool = len(s.Doc.Security) > 0

	for path, pathItem := range s.Doc.Paths.Map() {
		if pathItem == nil {
			continue
		}

		inheritedPathParams := collectPathParams(nil, pathItem.Parameters)
		for methodLower, op := range pathItem.Operations() {
			if op == nil {
				continue
			}

			method := strings.ToUpper(methodLower)
			allPathParams := collectPathParams(inheritedPathParams, op.Parameters)

			requiresAuth := rootRequiresAuth
			if op.Security != nil {
				requiresAuth = len(*op.Security) > 0
			}
			requestContentTypes, requestExamples := extractRequests(op.RequestBody)
			responseContentTypes, responseExamples := extractResponses(op.Responses)

			hasPathParams := len(allPathParams) > 0
			isInstance := hasPathParams
			isCollection := !hasPathParams

			opType := classifyOperationType(method, hasPathParams)
			operations = append(operations, Operation{
				Method:             method,
				Path:               path,
				PathParameterNames: allPathParams,
				IsCollection:       isCollection,
				IsInstance:         isInstance,
				OperationType:      opType, // Optional
				RequiresAuth:       requiresAuth,
				Consumes:           requestContentTypes,
				Produces:           responseContentTypes,
				RequestExamples:    requestExamples,
				ResponseExamples:   responseExamples,
				Raw:                op,
			})
		}
	}

	return operations
}

func classifyOperationType(method string, hasPathParams bool) string {
	switch method {
	case "GET":
		if hasPathParams {
			return "read" // GET /users/123
		}
		return "list" // GET /users

	case "POST":
		if hasPathParams {
			return "action" // POST /users/123/verify
		}
		return "create" // POST /users

	case "PUT":
		return "replace" // PUT /users/123

	case "PATCH":
		return "update" // PATCH /users/123

	case "DELETE":
		if hasPathParams {
			return "delete" // DELETE /users/123
		}
		return "bulk_delete" // DELETE /users (dangerous!)

	default:
		return "other"
	}
}

func collectPathParams(existing []string, params openapi3.Parameters) []string {
	seen := map[string]struct{}{}

	var names []string

	add := func(name string) {
		name = strings.TrimSpace(name)

		if name == "" {
			return
		}

		if _, ok := seen[name]; !ok {
			seen[name] = struct{}{}
			names = append(names, name)
		}
	}

	for _, paramRef := range params {
		if paramRef == nil || paramRef.Value == nil {
			continue
		}
		if paramRef.Value.In == "path" {
			add(paramRef.Value.Name)
		}
	}

	for _, name := range existing {
		add(name)
	}

	return names
}

func extractRequests(requestBodyRef *openapi3.RequestBodyRef) ([]string, map[string][]byte) {
	var contentTypes []string
	examplesByType := map[string][]byte{}

	if requestBodyRef == nil || requestBodyRef.Value == nil {
		return contentTypes, examplesByType
	}

	for mediaType, media := range requestBodyRef.Value.Content {
		contentTypes = append(contentTypes, mediaType)

		// Prefer 'example'
		if media.Example != nil {
			if b, ok := toJSONBytes(media.Example); ok {
				examplesByType[mediaType] = b
				continue
			}
		}
		// Then first entry in 'examples'
		for _, exRef := range media.Examples {
			if exRef != nil && exRef.Value != nil {
				if b, ok := toJSONBytes(exRef.Value.Value); ok {
					examplesByType[mediaType] = b
					break
				}
			}
		}
		// Then schema.example
		if media.Schema != nil && media.Schema.Value != nil && media.Schema.Value.Example != nil && examplesByType[mediaType] == nil {
			if b, ok := toJSONBytes(media.Schema.Value.Example); ok {
				examplesByType[mediaType] = b
			}
		}
	}
	return contentTypes, examplesByType
}

func extractResponses(rs *openapi3.Responses) ([]string, map[string][]byte) {
	if rs == nil {
		return nil, map[string][]byte{}
	}

	seenCT := map[string]struct{}{}
	var contentTypes []string
	examplesByStatus := map[string][]byte{}

	gather := func(statusKey string, content openapi3.Content) {
		for mediaType, media := range content {
			if _, ok := seenCT[mediaType]; !ok {
				seenCT[mediaType] = struct{}{}
				contentTypes = append(contentTypes, mediaType)
			}
			// prefer .Example, then .Examples, then schema.Example
			if media.Example != nil {
				if b, ok := toJSONBytes(media.Example); ok {
					examplesByStatus[statusKey] = b
					continue
				}
			}
			for _, exRef := range media.Examples {
				if exRef != nil && exRef.Value != nil {
					if b, ok := toJSONBytes(exRef.Value.Value); ok {
						examplesByStatus[statusKey] = b
						break
					}
				}
			}
			if media.Schema != nil && media.Schema.Value != nil && media.Schema.Value.Example != nil && examplesByStatus[statusKey] == nil {
				if b, ok := toJSONBytes(media.Schema.Value.Example); ok {
					examplesByStatus[statusKey] = b
				}
			}
		}
	}

	// default response (if present)
	if def := rs.Default(); def != nil && def.Value != nil {
		gather("default", def.Value.Content)
	}

	// status-code responses via Map()
	for code, ref := range rs.Map() {
		if ref != nil && ref.Value != nil {
			gather(code, ref.Value.Content)
		}
	}

	return contentTypes, examplesByStatus
}

func toJSONBytes(v interface{}) ([]byte, bool) {
	switch t := v.(type) {
	case []byte:
		return t, true
	case string:
		trimmed := strings.TrimSpace(t)
		// If it looks like JSON (object/array/literals), pass through
		if strings.HasPrefix(trimmed, "{") || strings.HasPrefix(trimmed, "[") ||
			trimmed == "null" || trimmed == "true" || trimmed == "false" {
			return []byte(t), true
		}
		// Otherwise quote it to produce valid JSON
		b, _ := json.Marshal(t)
		return b, true
	default:
		b, err := json.Marshal(v)
		return b, err == nil
	}
}
