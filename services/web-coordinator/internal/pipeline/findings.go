package pipeline

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"

	"github.com/google/uuid"

	"github.com/brian-l-johnson/web-sec-pipeline/services/web-coordinator/internal/store"
)

// ---------------------------------------------------------------------------
// ZAP report parsing
// ---------------------------------------------------------------------------

// zapReport is the top-level structure of ZAP's traditional-json report.
type zapReport struct {
	Site []struct {
		Alerts []struct {
			Alert    string `json:"alert"`
			RiskDesc string `json:"riskdesc"` // e.g. "High (Medium)"
			Desc     string `json:"desc"`
			CWEID    string `json:"cweid"` // "0" when absent; ZAP emits as a JSON string
			Instances []struct {
				URI      string `json:"uri"`
				Evidence string `json:"evidence"`
			} `json:"instances"`
		} `json:"alerts"`
	} `json:"site"`
}

// zapRiskToSeverity maps ZAP riskdesc prefixes to our severity values.
func zapRiskToSeverity(riskdesc string) string {
	prefix := strings.ToLower(strings.SplitN(riskdesc, " ", 2)[0])
	switch prefix {
	case "critical":
		return "critical"
	case "high":
		return "high"
	case "medium":
		return "medium"
	case "low":
		return "low"
	default:
		return "info"
	}
}

// parseAndStoreZAPFindings reads the ZAP JSON report from reportPath and
// inserts one web_findings row per alert instance. Returns the number stored.
func (o *Orchestrator) parseAndStoreZAPFindings(ctx context.Context, jobID uuid.UUID, reportPath string) (int, error) {
	data, err := os.ReadFile(reportPath)
	if err != nil {
		return 0, fmt.Errorf("read zap report: %w", err)
	}

	var report zapReport
	if err := json.Unmarshal(data, &report); err != nil {
		return 0, fmt.Errorf("parse zap report json: %w", err)
	}

	count := 0
	for _, site := range report.Site {
		for _, alert := range site.Alerts {
			severity := zapRiskToSeverity(alert.RiskDesc)
			desc := strings.TrimSpace(alert.Desc)

			for _, inst := range alert.Instances {
				f := store.WebFinding{
					ID:       uuid.New(),
					JobID:    jobID,
					Tool:     "zap",
					Severity: severity,
					Title:    alert.Alert,
					URL:      inst.URI,
				}
				if desc != "" {
					f.Description = &desc
				}
				if ev := strings.TrimSpace(inst.Evidence); ev != "" {
					f.Evidence = &ev
				}
				if n, err := strconv.Atoi(alert.CWEID); err == nil && n > 0 {
					f.CWE = &n
				}

				if err := o.store.InsertFinding(ctx, f); err != nil {
					log.Printf("orchestrator: insert zap finding failed (job=%s url=%s): %v", jobID, inst.URI, err)
				} else {
					count++
				}
			}
		}
	}
	log.Printf("orchestrator: stored %d ZAP findings for job %s", count, jobID)
	return count, nil
}

// ---------------------------------------------------------------------------
// Nuclei report parsing
// ---------------------------------------------------------------------------

// nucleiResult represents one line of Nuclei's JSONL output.
type nucleiResult struct {
	TemplateID string `json:"template-id"`
	Info       struct {
		Name        string `json:"name"`
		Severity    string `json:"severity"`
		Description string `json:"description"`
		Classification struct {
			CWEID []string `json:"cwe-id"` // e.g. ["CWE-79"]
		} `json:"classification"`
	} `json:"info"`
	MatchedAt string `json:"matched-at"`
}

// parseCWE extracts the first integer CWE ID from strings like "CWE-79".
func parseCWE(ids []string) *int {
	for _, s := range ids {
		var n int
		if _, err := fmt.Sscanf(strings.ToUpper(strings.TrimPrefix(s, "CWE-")), "%d", &n); err == nil && n > 0 {
			return &n
		}
	}
	return nil
}

// nucleiSeverityNorm normalises Nuclei severity to our enum values.
func nucleiSeverityNorm(s string) string {
	switch strings.ToLower(s) {
	case "critical":
		return "critical"
	case "high":
		return "high"
	case "medium":
		return "medium"
	case "low":
		return "low"
	default:
		return "info"
	}
}

// parseAndStoreNucleiFindings reads Nuclei's JSON array output (-json-export)
// and inserts findings. Returns the number stored.
func (o *Orchestrator) parseAndStoreNucleiFindings(ctx context.Context, jobID uuid.UUID, reportPath string) (int, error) {
	data, err := os.ReadFile(reportPath)
	if err != nil {
		return 0, fmt.Errorf("read nuclei report: %w", err)
	}

	var results []nucleiResult
	if err := json.Unmarshal(data, &results); err != nil {
		return 0, fmt.Errorf("parse nuclei report json: %w", err)
	}

	count := 0
	for _, result := range results {
		finding := store.WebFinding{
			ID:         uuid.New(),
			JobID:      jobID,
			Tool:       "nuclei",
			Severity:   nucleiSeverityNorm(result.Info.Severity),
			Title:      result.Info.Name,
			URL:        result.MatchedAt,
			TemplateID: &result.TemplateID,
			CWE:        parseCWE(result.Info.Classification.CWEID),
		}
		if desc := strings.TrimSpace(result.Info.Description); desc != "" {
			finding.Description = &desc
		}

		if err := o.store.InsertFinding(ctx, finding); err != nil {
			log.Printf("orchestrator: insert nuclei finding failed (job=%s url=%s): %v", jobID, result.MatchedAt, err)
		} else {
			count++
		}
	}
	log.Printf("orchestrator: stored %d Nuclei findings for job %s", count, jobID)
	return count, nil
}
