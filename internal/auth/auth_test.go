package auth 

import (
	"errors"
	"net/http"
	"testing"
)

func TestGetAPIKey(t *testing.T){
	tests := []struct {
		name          string
		headers       http.Header
		expectedKey   string
		expectError   bool
		expectedError error
	}{
		{
			name:          "Valid API Key",
			headers:       http.Header{"Authorization": []string{"ApiKey my-valid-api-key"}},
			expectedKey:   "my-valid-api-key",
			expectError:   false,
		},
		{
			name:          "No Authorization Header",
			headers:       http.Header{},
			expectedKey:   "",
			expectError:   true,
			expectedError: ErrNoAuthHeaderIncluded,
		},
		{
			name:          "Malformed Authorization Header",
			headers:       http.Header{"Authorization": []string{"MalformedHeader"}},
			expectedKey:   "",
			expectError:   true,
			expectedError: errors.New("malformed authorization header"),
		},
		{
			name:          "Missing API Key",
			headers:       http.Header{"Authorization": []string{"ApiKey"}},
			expectedKey:   "",
			expectError:   true,
			expectedError: errors.New("malformed authorization header"),
		},
		{
			name:          "Invalid Authorization Type",
			headers:       http.Header{"Authorization": []string{"Bearer some-token"}},
			expectedKey:   "",
			expectError:   true,
			expectedError: errors.New("malformed authorization header"),
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			key, err := GetAPIKey(test.headers)

			if test.expectError {
				if err == nil {
					t.Fatalf("expected an error but got none")
				}

				if err.Error() != test.expectedError.Error() {
					t.Errorf("expected error %q, got %q", test.expectedError, err)
				}
			} else {
				if err != nil {
					t.Fatalf("expected no error but got %q", err)
				}

				if key != test.expectedKey {
					t.Errorf("expected key %q, got %q", test.expectedKey, key)
				}
			}
		})
	} 
}