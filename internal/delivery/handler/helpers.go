package handler

import (
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/Sifr-Dev/GO_DB/internal/delivery/handler/middleware"
)

const defaultMaxBodyBytes int64 = 1 << 20

var (
	ErrUnsupportedMediaType = errors.New("request content type must be application/json")
	ErrBodyTooLarge         = errors.New("request body is too large")
	ErrTrailingJSON         = errors.New("request body must contain exactly one JSON value")
)

// decodeJSON applies a strict, bounded JSON contract to request bodies.
// It rejects unsupported media types, oversized bodies, unknown fields, and
// trailing JSON values.
func decodeJSON(w http.ResponseWriter, r *http.Request, v interface{}, maxBodyBytes int64) error {
	if maxBodyBytes <= 0 {
		maxBodyBytes = defaultMaxBodyBytes
	}

	mediaType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" {
		return ErrUnsupportedMediaType
	}
	if r.ContentLength > maxBodyBytes {
		return ErrBodyTooLarge
	}

	var body io.Reader = r.Body
	if w != nil {
		body = http.MaxBytesReader(w, r.Body, maxBodyBytes)
	} else {
		body = io.LimitReader(r.Body, maxBodyBytes+1)
	}

	decoder := json.NewDecoder(body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(v); err != nil {
		var maxBytesError *http.MaxBytesError
		if errors.As(err, &maxBytesError) {
			return ErrBodyTooLarge
		}
		return err
	}

	var trailing json.RawMessage
	if err := decoder.Decode(&trailing); err != io.EOF {
		if err == nil {
			return ErrTrailingJSON
		}
		var maxBytesError *http.MaxBytesError
		if errors.As(err, &maxBytesError) {
			return ErrBodyTooLarge
		}
		return err
	}
	return nil
}

func respondDecodeError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, ErrUnsupportedMediaType):
		respondError(w, http.StatusUnsupportedMediaType, "content type must be application/json")
	case errors.Is(err, ErrBodyTooLarge):
		respondError(w, http.StatusRequestEntityTooLarge, "request body is too large")
	default:
		respondError(w, http.StatusBadRequest, "invalid request body")
	}
}

func getUserID(r *http.Request) *uuid.UUID {
	id := middleware.GetUserID(r.Context())
	if id == uuid.Nil {
		return nil
	}
	return &id
}

func parseUUIDParam(r *http.Request, param string) (uuid.UUID, error) {
	return uuid.Parse(chi.URLParam(r, param))
}
