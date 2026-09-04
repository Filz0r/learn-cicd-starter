package auth

import (
	"errors"
	"net/http"
	"testing"
)

func TestGetAPIKey_NoAuthHeader(t *testing.T) {
	headers := http.Header{}

	got, err := GetAPIKey(headers)
	if !errors.Is(err, ErrNoAuthHeaderIncluded) {
		t.Errorf("expected ErrNoAuthHeaderIncluded, got %v", err)
	}
	if got != "" {
		t.Errorf("expected empty key, got %q", got)
	}
}

func TestGetAPIKey_MalformedHeader(t *testing.T) {
	headers := http.Header{}
	headers.Set("Authorization", "Bearer some-token")

	got, err := GetAPIKey(headers)
	if err == nil {
		t.Fatalf("expected error for malformed header, got nil")
	}
	if errors.Is(err, ErrNoAuthHeaderIncluded) {
		t.Errorf("expected malformed header error, got ErrNoAuthHeaderIncluded instead")
	}
	if got != "" {
		t.Errorf("expected empty key, got %q", got)
	}
}

func TestGetAPIKey_ValidHeader(t *testing.T) {
	headers := http.Header{}
	headers.Set("Authorization", "ApiKey my-secret-key")

	got, err := GetAPIKey(headers)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "my-secret-key" {
		t.Errorf("expected %q, got %q", "my-secret-key", got)
	}
}
