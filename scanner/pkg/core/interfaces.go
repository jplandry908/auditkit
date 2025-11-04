package core

import (
	"context"
	"time"
)

// Provider defines the interface that all cloud providers must implement
type Provider interface {
	// Name returns the provider name (aws, gcp, azure, m365)
	Name() string

	// Initialize sets up the provider with credentials/config
	Initialize(profile string) error

	// GetAccountID returns the account/project/subscription identifier
	GetAccountID(ctx context.Context) string

	// Scan executes compliance checks for the given framework
	Scan(ctx context.Context, services []string, framework string, verbose bool) ([]ScanResult, error)

	// Close cleans up any resources
	Close() error
}

// ScanResult represents a single compliance check result
type ScanResult struct {
	Control           string            `json:"control"`
	Name              string            `json:"name"`
	Category          string            `json:"category"`
	Status            string            `json:"status"`
	Severity          string            `json:"severity"`
	Evidence          string            `json:"evidence"`
	Remediation       string            `json:"remediation"`
	RemediationDetail string            `json:"remediation_detail"`
	ScreenshotGuide   string            `json:"screenshot_guide"`
	ConsoleURL        string            `json:"console_url"`
	Priority          string            `json:"priority"`
	Frameworks        map[string]string `json:"frameworks"`
}

// ComplianceResult represents the full scan results
type ComplianceResult struct {
	Timestamp       time.Time       `json:"timestamp"`
	Provider        string          `json:"provider"`
	Framework       string          `json:"framework"`
	AccountID       string          `json:"account_id"`
	Score           float64         `json:"score"`
	TotalControls   int             `json:"total_controls"`
	PassedControls  int             `json:"passed_controls"`
	FailedControls  int             `json:"failed_controls"`
	Controls        []ControlResult `json:"controls"`
	Recommendations []string        `json:"recommendations"`
}

// ControlResult represents a control in the final report
type ControlResult struct {
	ID                string            `json:"id"`
	Name              string            `json:"name"`
	Category          string            `json:"category"`
	Severity          string            `json:"severity"`
	Status            string            `json:"status"`
	Evidence          string            `json:"evidence"`
	Remediation       string            `json:"remediation"`
	RemediationDetail string            `json:"remediation_detail"`
	Priority          string            `json:"priority"`
	Impact            string            `json:"impact"`
	ScreenshotGuide   string            `json:"screenshot_guide"`
	ConsoleURL        string            `json:"console_url"`
	Frameworks        map[string]string `json:"frameworks"`
}

// Scanner orchestrates compliance scanning across providers
type Scanner interface {
	// ScanProvider scans a single provider
	ScanProvider(ctx context.Context, provider Provider, services []string, framework string, verbose bool) (ComplianceResult, error)

	// ScanMultiProvider scans multiple providers and aggregates results
	ScanMultiProvider(ctx context.Context, providers []Provider, services []string, framework string, verbose bool) (ComplianceResult, error)
}

// Reporter formats and outputs scan results
type Reporter interface {
	// Format returns the format name (text, json, html, pdf, csv)
	Format() string

	// Generate creates the report output
	Generate(result ComplianceResult, output string, verbose bool) error
}

// Command represents a CLI command
type Command interface {
	// Name returns the command name
	Name() string

	// Description returns a brief description
	Description() string

	// Execute runs the command
	Execute(args []string) error
}
