package ollama

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
)

// Client represents the Ollama API client
type Client struct {
	BaseURL string
}

// NewClient creates a new Ollama client
func NewClient(baseURL string) *Client {
	return &Client{BaseURL: baseURL}
}

// GenerateRequest represents the request body for the Ollama API
type GenerateRequest struct {
	Model  string `json:"model"`
	Prompt string `json:"prompt"`
}

// GenerateResponse represents the response from the Ollama API
type GenerateResponse struct {
	Response string `json:"response"`
}

// Generate sends a prompt to the Ollama API and returns the response
func (c *Client) Generate(ctx context.Context, req GenerateRequest) (*GenerateResponse, error) {
	url := fmt.Sprintf("%s/api/generate", c.BaseURL)
	reqBody, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	resp, err := http.Post(url, "application/json", bytes.NewBuffer(reqBody))
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("API request failed with status: %s", resp.Status)
	}

	var generateResp GenerateResponse
	if err := json.NewDecoder(resp.Body).Decode(&generateResp); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return &generateResp, nil
}
