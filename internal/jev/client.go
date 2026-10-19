// Package jev is a minimal client for System One decision models: Jev,
// TypeSafe's model on OpenRouter, or a self-hosted basal-serve (for example
// Remek/basal-omni-1.0-ultra), which speaks the same API. The model takes
// free-form state plus typed questions (choice / score / noul) and returns
// calibrated probabilities.
package jev

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
)

const (
	DefaultURL   = "https://openrouter.ai/api/v1/systemone"
	DefaultModel = "jev-1.13"

	// EstimatedUSDPerInputToken is used when OpenRouter does not report cost.
	EstimatedUSDPerInputToken = 0.042 / 1_000_000

	maxResponse = 1 << 20
)

// Question is one typed question. Criteria is:
//   - choice: map[id]description (2–255 options)
//   - score:  []string levels, lowest first (2–10)
//   - noul:   nil or map{"true": ..., "false": ...}
type Question struct {
	Type         string `json:"type"`
	Instructions string `json:"instructions"`
	Criteria     any    `json:"criteria,omitempty"`
}

func Choice(instructions string, options map[string]string) Question {
	return Question{Type: "choice", Instructions: instructions, Criteria: options}
}

func Score(instructions string, levels []string) Question {
	return Question{Type: "score", Instructions: instructions, Criteria: levels}
}

func Noul(instructions, ifTrue, ifFalse string) Question {
	return Question{Type: "noul", Instructions: instructions, Criteria: map[string]string{"true": ifTrue, "false": ifFalse}}
}

// Answer covers all three answer types; unused fields stay zero.
type Answer struct {
	Type          string             `json:"type"`
	Choice        string             `json:"choice"`
	Score         float64            `json:"score"`
	Noul          float64            `json:"noul"`
	Probabilities map[string]float64 `json:"probabilities"`
	Confidence    float64            `json:"confidence"`
}

type Result struct {
	Answers     map[string]Answer
	InputTokens int
	Cost        float64 // USD
	Estimated   bool    // cost estimated from tokens
	Model       string
	Duration    time.Duration
}

// Error carries the upstream status; the message never contains the API key.
type Error struct {
	Status int
	Msg    string
}

func (e *Error) Error() string { return e.Msg }

type Client struct {
	URL     string
	APIKey  string
	Model   string
	Timeout time.Duration
	HTTP    *http.Client
	// SelfHosted marks a basal-serve on the operator's own hardware: there is
	// no per-token price, so an unreported cost is 0 rather than estimated.
	SelfHosted bool
}

// Ask sends one request. It retries once on 429/5xx when the deadline allows.
func (c *Client) Ask(ctx context.Context, state string, questions map[string]Question) (Result, error) {
	body, err := json.Marshal(map[string]any{"model": c.Model, "state": state, "questions": questions})
	if err != nil {
		return Result{}, err
	}
	timeout := c.Timeout
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	start := time.Now()
	status, payload, retryAfter, err := c.send(ctx, body)
	if err == nil && (status == http.StatusTooManyRequests || status >= 500) {
		wait := min(max(retryAfter, 300*time.Millisecond), 2*time.Second)
		if dl, ok := ctx.Deadline(); ok && time.Until(dl) > wait+time.Second {
			select {
			case <-time.After(wait):
				status, payload, _, err = c.send(ctx, body)
			case <-ctx.Done():
			}
		}
	}
	if err != nil {
		return Result{}, err
	}
	if status != http.StatusOK {
		return Result{}, &Error{Status: status, Msg: fmt.Sprintf("jev: upstream status %d: %s", status, c.redact(upstreamMessage(payload)))}
	}

	var data struct {
		Model   string            `json:"model"`
		Answers map[string]Answer `json:"answers"`
		Usage   struct {
			InputTokens int      `json:"input_tokens"`
			Cost        *float64 `json:"cost"`
		} `json:"usage"`
	}
	if err := json.Unmarshal(payload, &data); err != nil || data.Answers == nil {
		return Result{}, &Error{Status: http.StatusBadGateway, Msg: "jev: unexpected response: " + c.redact(string(payload))}
	}
	res := Result{Answers: data.Answers, InputTokens: data.Usage.InputTokens, Model: data.Model, Duration: time.Since(start)}
	if res.Model == "" {
		res.Model = c.Model
	}
	if data.Usage.Cost != nil {
		res.Cost = *data.Usage.Cost
	} else if !c.SelfHosted {
		res.Cost = float64(res.InputTokens) * EstimatedUSDPerInputToken
		res.Estimated = true
	}
	return res, nil
}

func (c *Client) send(ctx context.Context, body []byte) (int, []byte, time.Duration, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.URL, bytes.NewReader(body))
	if err != nil {
		return 0, nil, 0, err
	}
	if c.APIKey != "" { // basal-serve has no auth; a gateway in front may
		req.Header.Set("Authorization", "Bearer "+c.APIKey)
	}
	req.Header.Set("Content-Type", "application/json")
	hc := c.HTTP
	if hc == nil {
		hc = http.DefaultClient
	}
	resp, err := hc.Do(req)
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) {
			return 0, nil, 0, &Error{Status: http.StatusGatewayTimeout, Msg: "jev: timeout"}
		}
		return 0, nil, 0, &Error{Status: http.StatusBadGateway, Msg: "jev: connection failed: " + c.redact(err.Error())}
	}
	defer resp.Body.Close()
	payload, err := io.ReadAll(io.LimitReader(resp.Body, maxResponse))
	if err != nil {
		return 0, nil, 0, &Error{Status: http.StatusBadGateway, Msg: "jev: reading response failed"}
	}
	var retry time.Duration
	if s, err := strconv.Atoi(strings.TrimSpace(resp.Header.Get("Retry-After"))); err == nil && s > 0 {
		retry = time.Duration(s) * time.Second
	}
	return resp.StatusCode, payload, retry, nil
}

func upstreamMessage(payload []byte) string {
	var v struct {
		Error   any    `json:"error"`
		Message string `json:"message"`
	}
	if json.Unmarshal(payload, &v) == nil {
		switch e := v.Error.(type) {
		case string:
			return e
		case map[string]any:
			if m, ok := e["message"].(string); ok {
				return m
			}
		}
		if v.Message != "" {
			return v.Message
		}
	}
	return string(payload)
}

// redact strips the API key and truncates, so upstream text is safe to log.
func (c *Client) redact(s string) string {
	if c.APIKey != "" {
		s = strings.ReplaceAll(s, c.APIKey, "[key]")
	}
	s = strings.Join(strings.Fields(s), " ")
	if len(s) > 300 {
		s = s[:300] + "…"
	}
	return s
}
