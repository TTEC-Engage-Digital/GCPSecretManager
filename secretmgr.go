// Package GCPSecretManager provides a client for interacting with Google Cloud Secret Manager.
// It offers functionality to retrieve secrets and automatically load them into
// environment variables. The package handles authentication, secret retrieval,
// and environment variable management with proper error handling and logging.
//
// Basic usage:
//
//	ctx := context.Background()
//	client, err := GCPSecretManager.NewSecret(ctx)
//	if err != nil {
//	    log.Fatal(err)
//	}
//	defer client.Close()
//
//	// Load secrets into environment variables
//	err = client.LoadSecretToEnv(ctx)
//
// Required environment variables:
//   - GCP_PROJECT_ID: The Google Cloud project Id
//   - SECRET_NAME: The name of the secret in Secret Manager
//   - SECRET_VERSION: The version of the secret (defaults to "latest")
package GCPSecretManager

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	secretmanager "cloud.google.com/go/secretmanager/apiv1"
	secretmanagerpb "cloud.google.com/go/secretmanager/apiv1/secretmanagerpb"
	"github.com/googleapis/gax-go/v2"
	"github.com/rs/zerolog/log"
	"google.golang.org/api/option"
)

// ConfigError represents configuration-related errors that occur when required
// environment variables are missing.
type ConfigError struct {
	MissingField string
}

// Error implements the error interface for ConfigError
func (e ConfigError) Error() string {
	return fmt.Sprintf("missing required environment variable: %s", e.MissingField)
}

// Config holds the configuration parameters required for connecting to
// Google Cloud Secret Manager.
type Config struct {
	// ProjectID is the Google Cloud project identifier
	ProjectID string
	// SecretName is the name of the secret in Secret Manager, do not include the total path
	// will be appended to the path in the format "projects/PROJECT_ID/secrets/SECRET_NAME"
	SecretName string
	// SecretVersion is the version of the secret to retrieve
	// If not specified, defaults to "latest"
	SecretVersion string
}

type secretManagerClient interface {
	AccessSecretVersion(ctx context.Context, req *secretmanagerpb.AccessSecretVersionRequest, opts ...gax.CallOption) (*secretmanagerpb.AccessSecretVersionResponse, error)
	Close() error
}

type clientFactoryFunc func(ctx context.Context, opts ...option.ClientOption) (secretManagerClient, error)

var defaultClientFactory clientFactoryFunc = func(ctx context.Context, opts ...option.ClientOption) (secretManagerClient, error) {
	return secretmanager.NewClient(ctx, opts...)
}

var newScanner = func(input string) *bufio.Scanner {
	return bufio.NewScanner(bytes.NewBufferString(input))
}

// Client represents a Secret Manager client with associated configuration.
// It handles the connection to Google Cloud Secret Manager and provides
// methods for secret retrieval and environment variable management.
type Client struct {
	client secretManagerClient
	config *Config
}

// ParseError represents errors that occur during the parsing of secret values
// when loading them into environment variables.
type ParseError struct {
	// Line contains the problematic line from the secret
	Line string
	// LineNum indicates the line number where the error occurred
	LineNum int
	// Reason provides a description of why the parsing failed
	Reason string
}

func (e ParseError) Error() string {
	return fmt.Sprintf("invalid format at line %d (%s): %s", e.LineNum, e.Line, e.Reason)
}

// NewConfig creates a new Config instance by reading required values
// from environment variables. Returns an error if required variables
// are missing.
//
// Returns:
// - A pointer to a Config struct containing the configuration parameters.
// - An error if any required environment variable is missing.
func NewConfig() (*Config, error) {
	// Retrieve and validate the GCP_PROJECT_ID environment variable.
	// Returns an error if the variable is not set.
	projectID := os.Getenv("GCP_PROJECT_ID")
	if projectID == "" {
		return nil, ConfigError{MissingField: "GCP_PROJECT_ID"}
	}

	// Retrieve and validate the SECRET_NAME environment variable.
	// Returns an error if the variable is not set.
	secretName := os.Getenv("SECRET_NAME")
	if secretName == "" {
		return nil, ConfigError{MissingField: "SECRET_NAME"}
	}

	// Retrieve the SECRET_VERSION environment variable.
	// Default to "latest" if not specified.
	secretVersion := os.Getenv("SECRET_VERSION")
	if secretVersion == "" {
		secretVersion = "latest"
	}

	// Create and return a new Config struct with the retrieved values.
	return &Config{
		ProjectID:     projectID,
		SecretName:    secretName,
		SecretVersion: secretVersion,
	}, nil
}

// NewSecret initializes a new Secret Manager client with the provided context.
// It creates the necessary configuration and establishes a connection to
// Google Cloud Secret Manager.
//
// Parameters:
// - ctx: The context for the request, used for cancellation and timeouts.
//
// Returns:
// - A pointer to a Client struct representing the Secret Manager client.
// - An error if the configuration creation or client initialization fails.
func NewSecret(ctx context.Context) (*Client, error) {
	// Create a new Config instance by reading required values from environment variables.
	// Returns an error if required variables are missing.
	config, err := NewConfig()
	if err != nil {
		return nil, fmt.Errorf("failed to create config: %w", err)
	}

	// Initialize a new Secret Manager client with the provided context.
	// Returns an error if the client initialization fails.
	client, err := defaultClientFactory(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to create secret manager client: %w", err)
	}

	// Return a new Client struct with the initialized Secret Manager client and configuration.
	return &Client{
		client: client,
		config: config,
	}, nil
}

// GetSecret retrieves the secret value from Secret Manager using the configured
// secret name and version. It returns the secret value as a string.
//
// Parameters:
// - ctx: The context for the request, used for cancellation and timeouts.
//
// Returns:
// - A string containing the secret value.
// - An error if the secret retrieval fails.
func (c *Client) GetSecret(ctx context.Context) (string, error) {
	// Create the secret path using the project Id, secret name, and secret version
	name := fmt.Sprintf("projects/%s/secrets/%s/versions/%s",
		c.config.ProjectID,
		c.config.SecretName,
		c.config.SecretVersion,
	)

	// Create the request to access the secret version
	req := &secretmanagerpb.AccessSecretVersionRequest{
		Name: name,
	}

	// Add a timeout to the context to limit the duration of the API call
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	// Call the Secret Manager API to access the secret version
	result, err := c.client.AccessSecretVersion(ctx, req)
	if err != nil {
		return "", fmt.Errorf("failed to access secret: %w", err)
	}

	// Return the secret payload data as a string
	return string(result.Payload.Data), nil
}

// Close releases any resources held by the Secret Manager client.
// It should be called when the client is no longer needed.
//
// Returns:
// - An error if the client fails to close properly, otherwise nil.
func (c *Client) Close() error {
	if err := c.client.Close(); err != nil {
		return fmt.Errorf("failed to close secret manager client: %w", err)
	}
	return nil
}

// LoadSecretToEnv retrieves the secret from Secret Manager and sets each line
// as an environment variable. The secret content should be in the format:
//
//	KEY=VALUE
//
// Each line should contain exactly one key-value pair.
// Empty lines are skipped, and malformed lines are logged as warnings.
//
// Parameters:
// - ctx: The context for the request, used for cancellation and timeouts.
//
// Returns:
// - An error if the secret retrieval or environment variable setting fails.
func (c *Client) LoadSecretToEnv(ctx context.Context) error {
	// Get the secret content
	content, err := c.GetSecret(ctx)
	if err != nil {
		return fmt.Errorf("failed to retrieve secret: %w", err)
	}

	// Create a scanner to read line by line
	scanner := newScanner(content)
	lineNum := 0

	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())

		// Skip empty lines
		if line == "" {
			continue
		}

		// Parse and set environment variable
		if err := parseAndSetEnv(line, lineNum); err != nil {
			return fmt.Errorf("failed to set environment variable: %w", err)
		}
	}

	if err := scanner.Err(); err != nil {
		return fmt.Errorf("error reading secret content: %w", err)
	}

	return nil
}

// parseAndSetEnv parses a single line of the secret content and sets it
// as an environment variable. The line should be in the format KEY=VALUE.
// It logs successful operations and returns any parsing or setting errors.
//
// Parameters:
// - line: A string containing the line to be parsed and set as an environment variable.
// - lineNum: An integer representing the line number, used for error reporting.
//
// Returns:
// - An error if the line is malformed or if setting the environment variable fails.
func parseAndSetEnv(line string, lineNum int) error {
	// Split the line on the first '=' character only
	parts := strings.SplitN(line, "=", 2)
	if len(parts) != 2 {
		// Return a ParseError if the line does not contain exactly one '=' character
		return ParseError{
			Line:    line,
			LineNum: lineNum,
			Reason:  "line must contain exactly one '=' character",
		}
	}

	key := strings.TrimSpace(parts[0])
	value := strings.TrimSpace(parts[1])

	// Validate the key
	if key == "" {
		// Return a ParseError if the key is empty
		return ParseError{
			Line:    line,
			LineNum: lineNum,
			Reason:  "empty key is not allowed",
		}
	}

	// Unpack the square bracket if value has equal sign
	if strings.Contains(value, "=") {
		if len(value) > 2 && value[0] == '[' && value[len(value)-1] == ']' {
			value = value[1 : len(value)-1]
		} else {
			return ParseError{
				Line:    line,
				LineNum: lineNum,
				Reason:  "invalid specific key-value pair",
			}
		}
	}

	// Set the environment variable
	if err := os.Setenv(key, value); err != nil {
		return ParseError{
			Line:    line,
			LineNum: lineNum,
			Reason:  fmt.Sprintf("failed to set environment variable: %v", err),
		}
	}
	log.Info().Str("key", key).Msg("Successfully set environment variable")

	return nil
}
