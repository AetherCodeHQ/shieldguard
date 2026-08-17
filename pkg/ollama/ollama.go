package ollama

import (
    "bytes"
    "encoding/json"
    "fmt"
    "io"
    "net/http"
    "strings"
    "time"

    "github.com/Qyroxen/shieldguard/pkg/scanner"
)

type Client struct {
    BaseURL string
    Model   string
    HTTP    *http.Client
}

type GenerateRequest struct {
    Model  string `json:"model"`
    Prompt string `json:"prompt"`
    Stream bool   `json:"stream"`
}

type GenerateResponse struct {
    Response string `json:"response"`
    Error    string `json:"error,omitempty"`
}

func NewClient(baseURL, model string) *Client {
    return &Client{
        BaseURL: baseURL,
        Model:   model,
        HTTP:    &http.Client{Timeout: 90 * time.Second},
    }
}

func (c *Client) AnalyzeAndFix(v scanner.Vulnerability) (string, string, error) {
    prompt := fmt.Sprintf(
        "You are a SAST security expert. Fix the following vulnerable code line.\n"+
            "File: %s (Line %d)\n"+
            "Vulnerability Type: %s\n"+
            "Vulnerable Code: %s\n\n"+
            "Respond strictly in this format:\n"+
            "ANALYSIS: <one sentence explanation of the security risk>\n"+
            "FIX: <single replacement line of code without backticks>",
        v.FilePath, v.Line, v.Type, v.Snippet,
    )

    reqBody := GenerateRequest{
        Model:  c.Model,
        Prompt: prompt,
        Stream: false,
    }

    data, err := json.Marshal(reqBody)
    if err != nil {
        return "", "", err
    }

    resp, err := c.HTTP.Post(c.BaseURL+"/api/generate", "application/json", bytes.NewBuffer(data))
    if err != nil {
        return "", "", err
    }
    defer resp.Body.Close()

    bodyBytes, err := io.ReadAll(resp.Body)
    if err != nil {
        return "", "", err
    }

    if resp.StatusCode != http.StatusOK {
        var errResp struct {
            Error string `json:"error"`
        }
        _ = json.Unmarshal(bodyBytes, &errResp)
        if errResp.Error != "" {
            return "", "", fmt.Errorf("ollama hatasi (http %d): %s", resp.StatusCode, errResp.Error)
        }
        return "", "", fmt.Errorf("ollama sunucusu hata dondurdu: status %d", resp.StatusCode)
    }

    var genResp GenerateResponse
    if err := json.Unmarshal(bodyBytes, &genResp); err != nil {
        return "", "", err
    }

    if genResp.Error != "" {
        return "", "", fmt.Errorf("ollama hatasi: %s", genResp.Error)
    }

    text := strings.TrimSpace(genResp.Response)
    var analysis, fix string

    lines := strings.Split(text, "\n")
    for _, l := range lines {
        l = strings.TrimSpace(l)
        if strings.HasPrefix(l, "ANALYSIS:") {
            analysis = strings.TrimSpace(strings.TrimPrefix(l, "ANALYSIS:"))
        } else if strings.HasPrefix(l, "FIX:") {
            fix = strings.TrimSpace(strings.TrimPrefix(l, "FIX:"))
            fix = strings.Trim(fix, "`")
            fix = strings.TrimPrefix(fix, "go")
            fix = strings.TrimSpace(fix)
        }
    }

    if analysis == "" {
        analysis = text
    }

    return analysis, fix, nil
}
