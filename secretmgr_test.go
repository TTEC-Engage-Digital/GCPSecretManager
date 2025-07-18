package GCPSecretManager

import (
	"bufio"
	"context"
	"fmt"
	"testing"

	secretmanager "cloud.google.com/go/secretmanager/apiv1"
	secretmanagerpb "cloud.google.com/go/secretmanager/apiv1/secretmanagerpb"
	"github.com/googleapis/gax-go/v2"
	"github.com/stretchr/testify/assert"
	"google.golang.org/api/option"
)

type mockSecretManagerClient struct {
	secretPayload string
	isSuccess     bool
}

func (m *mockSecretManagerClient) AccessSecretVersion(ctx context.Context, req *secretmanagerpb.AccessSecretVersionRequest, opts ...gax.CallOption) (*secretmanagerpb.AccessSecretVersionResponse, error) {
	if m.isSuccess {
		return &secretmanagerpb.AccessSecretVersionResponse{
			Payload: &secretmanagerpb.SecretPayload{
				Data: []byte(m.secretPayload),
			},
		}, nil
	}
	return nil, fmt.Errorf("access error")
}

func (m *mockSecretManagerClient) Close() error {
	return nil
}

type brokenReader struct{}

func (brokenReader) Read(p []byte) (int, error) {
	return 0, fmt.Errorf("simulated read failure")
}

func TestNewSecret(t *testing.T) {
	originDefaultClientFactory := defaultClientFactory
	defer func() {
		defaultClientFactory = originDefaultClientFactory
	}()

	ctx := context.Background()

	testCases := []struct {
		name        string
		envs        map[string]string
		runFn       func()
		expectedErr error
	}{
		{
			name: "success to create",
			envs: map[string]string{
				"GCP_PROJECT_ID": "test-id",
				"SECRET_NAME":    "test-name",
				"SECRET_VERSION": "test-version",
			},
			runFn: func() {
				defaultClientFactory = func(ctx context.Context, opts ...option.ClientOption) (secretManagerClient, error) {
					return &secretmanager.Client{}, nil
				}
			},
			expectedErr: nil,
		},
		{
			name: "fail to get GCP_Project_ID",
			envs: map[string]string{},
			expectedErr: ConfigError{
				MissingField: "GCP_PROJECT_ID",
			},
		},
		{
			name: "fail to create secret manager client",
			envs: map[string]string{
				"GCP_PROJECT_ID": "test-id",
				"SECRET_NAME":    "test-name",
			},
			runFn: func() {
				defaultClientFactory = func(ctx context.Context, opts ...option.ClientOption) (secretManagerClient, error) {
					return nil, fmt.Errorf("error")
				}
			},
			expectedErr: fmt.Errorf("failed to create secret manager client"),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			for key, value := range tc.envs {
				t.Setenv(key, value)
			}

			if tc.runFn != nil {
				tc.runFn()
			}

			client, err := NewSecret(ctx)
			if tc.expectedErr != nil {
				assert.Contains(t, err.Error(), tc.expectedErr.Error())
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, client)
			}
		})
	}
}

func TestLoadSecretToEnv(t *testing.T) {
	ctx := context.Background()

	originalScanner := newScanner
	defer func() { newScanner = originalScanner }()

	testCases := []struct {
		name        string
		mockClient  *Client
		runFn       func()
		expectedErr error
	}{
		{
			name: "success load with valid configuration",
			mockClient: &Client{
				client: &mockSecretManagerClient{
					secretPayload: "FOO=bar",
					isSuccess:     true,
				},
				config: &Config{},
			},
		},
		{
			name: "fail to access gcp secret manager",
			mockClient: &Client{
				client: &mockSecretManagerClient{
					isSuccess: false,
				},
				config: &Config{},
			},
			expectedErr: fmt.Errorf("failed to retrieve secret"),
		},
		{
			name: "fail to set environment variable",
			mockClient: &Client{
				client: &mockSecretManagerClient{
					secretPayload: "FOO=bar=baz",
					isSuccess:     true,
				},
				config: &Config{},
			},
			expectedErr: fmt.Errorf("failed to set environment variable"),
		},
		{
			name: "fail to read secret content",
			mockClient: &Client{
				client: &mockSecretManagerClient{
					isSuccess: true,
				},
				config: &Config{},
			},
			runFn: func() {
				newScanner = func(input string) *bufio.Scanner {
					return bufio.NewScanner(brokenReader{})
				}
			},
			expectedErr: fmt.Errorf("error reading secret content"),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.runFn != nil {
				tc.runFn()
			}
			err := tc.mockClient.LoadSecretToEnv(ctx)
			if err != nil {
				assert.Contains(t, err.Error(), tc.expectedErr.Error())
			} else {
				assert.Nil(t, tc.expectedErr)
			}
		})
	}
}
