package generativeai

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
)

// Client represents the Gemini API client
type Client struct {
	APIKey string
}

// NewClient creates a new Gemini client
func NewClient(apiKey string) *Client {
	return &Client{APIKey: apiKey}
}

// GenerateTextRequest represents the request body for the Gemini API
type GenerateTextRequest struct {
	Model  string `json:"model"`
	Prompt string `json:"prompt"`
}

// GenerateTextResponse represents the response from the Gemini API
type GenerateTextResponse struct {
	Text string `json:"text"`
}

// GenerateText sends a prompt to the Gemini API and returns the response
func (c *Client) GenerateText(ctx context.Context, req GenerateTextRequest) (*GenerateTextResponse, error) {
	url := fmt.Sprintf("https://generativelanguage.googleapis.com/v1/models/%s:generateText?key=%s", req.Model, c.APIKey)
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

	var generateResp GenerateTextResponse
	if err := json.NewDecoder(resp.Body).Decode(&generateResp); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return &generateResp, nil
}