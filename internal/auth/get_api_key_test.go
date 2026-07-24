package auth

import (
	"errors"
	"net/http"
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	tests := []struct {
		name          string
		headers       http.Header
		expectedKey   string
		expectedError error
		expectErrText string
	}{
		{
			name:        "Valid ApiKey header",
			headers:     http.Header{"Authorization": []string{"ApiKey secret_key_123"}},
			expectedKey: "secret_key_123",
		},
		{
			name:          "Missing Authorization header",
			headers:       http.Header{},
			expectedError: ErrNoAuthHeaderIncluded,
		},
		{
			name:          "Malformed header - wrong prefix (Bearer)",
			headers:       http.Header{"Authorization": []string{"Bearer secret_key_123"}},
			expectErrText: "malformed authorization header",
		},
		{
			name:          "Malformed header - missing space/token",
			headers:       http.Header{"Authorization": []string{"ApiKey"}},
			expectErrText: "malformed authorization header",
		},
		{
			name:          "Empty Authorization header value",
			headers:       http.Header{"Authorization": []string{""}},
			expectedError: ErrNoAuthHeaderIncluded,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key, err := GetAPIKey(tt.headers)

			if tt.expectedError != nil && !errors.Is(err, tt.expectedError) {
				t.Fatalf("expected error %v, got %v", tt.expectedError, err)
			}

			if tt.expectErrText != "" {
				if err == nil || err.Error() != tt.expectErrText {
					t.Fatalf("expected error message %q, got %v", tt.expectErrText, err)
				}
			}

			if tt.expectedError == nil && tt.expectErrText == "" && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if key != tt.expectedKey {
				t.Errorf("expected key %q, got %q", tt.expectedKey, key)
			}
		})
	}

}
