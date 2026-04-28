package pipeline

import (
	"context"
	"encoding/json"
	"fmt"
	"html"
	"log"
	"os"
	"regexp"
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
			Alert      string `json:"alert"`
			RiskDesc   string `json:"riskdesc"`   // e.g. "High (Medium)"
			Desc       string `json:"desc"`
			CWEID      string `json:"cweid"`      // "0" when absent; ZAP emits as a JSON string
			Confidence string `json:"confidence"` // Low/Medium/High/Confirmed
			Solution   string `json:"solution"`
			Reference  string `json:"reference"`
			OtherInfo  string `json:"otherinfo"`
			PluginID   string `json:"pluginid"`
			WASCID     string `json:"wascid"`
			Instances  []struct {
				URI       string `json:"uri"`
				Evidence  string `json:"evidence"`
				Method    string `json:"method"`
				Param     string `json:"param"`
				Attack    string `json:"attack"`
				OtherInfo string `json:"otherinfo"`
			} `json:"instances"`
		} `json:"alerts"`
	} `json:"site"`
}

var htmlTagRe = regexp.MustCompile(`<[^>]*>`)

// cleanZAPText strips HTML tags and decodes HTML entities from ZAP text fields.
func cleanZAPText(s string) string {
	s = htmlTagRe.ReplaceAllString(s, "")
	s = html.UnescapeString(s)
	return strings.TrimSpace(s)
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

	count, errs := 0, 0
	for _, site := range report.Site {
		for _, alert := range site.Alerts {
			severity := zapRiskToSeverity(alert.RiskDesc)
			desc := cleanZAPText(alert.Desc)

			// Alert-level details shared by every instance.
			alertDetails := map[string]any{}
			if c := strings.TrimSpace(alert.Confidence); c != "" {
				alertDetails["confidence"] = c
			}
			if s := cleanZAPText(alert.Solution); s != "" {
				alertDetails["solution"] = s
			}
			if r := cleanZAPText(alert.Reference); r != "" {
				alertDetails["reference"] = r
			}
			if o := cleanZAPText(alert.OtherInfo); o != "" {
				alertDetails["other_info"] = o
			}
			if alert.PluginID != "" && alert.PluginID != "0" {
				alertDetails["plugin_id"] = alert.PluginID
			}
			if alert.WASCID != "" && alert.WASCID != "0" {
				alertDetails["wasc_id"] = alert.WASCID
			}

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

				// Merge instance-specific fields into details.
				d := copyMap(alertDetails)
				if inst.Method != "" {
					d["method"] = inst.Method
				}
				if inst.Param != "" {
					d["param"] = inst.Param
				}
				if inst.Attack != "" {
					d["attack"] = inst.Attack
				}
				if o := strings.TrimSpace(inst.OtherInfo); o != "" {
					d["instance_other_info"] = o
				}
				f.Details = marshalDetails(d)

				if err := o.store.InsertFinding(ctx, f); err != nil {
					log.Printf("orchestrator: insert zap finding failed (job=%s url=%s): %v", jobID, inst.URI, err)
					errs++
				} else {
					count++
				}
			}
		}
	}
	log.Printf("orchestrator: stored %d ZAP findings for job %s (%d insert errors)", count, jobID, errs)
	if errs > 0 {
		return count, fmt.Errorf("%d of %d ZAP findings failed to insert", errs, count+errs)
	}
	return count, nil
}

// ---------------------------------------------------------------------------
// Nuclei report parsing
// ---------------------------------------------------------------------------

const maxDetailBytes = 4096 // truncate large fields (request/response) before storing

// nucleiResult represents one entry in Nuclei's JSON array output.
type nucleiResult struct {
	TemplateID string `json:"template-id"`
	Info       struct {
		Name        string   `json:"name"`
		Author      []string `json:"author"`
		Tags        []string `json:"tags"`
		Reference   []string `json:"reference"`
		Severity    string   `json:"severity"`
		Description string   `json:"description"`
		Remediation string   `json:"remediation"`
		Classification struct {
			CWEID          []string `json:"cwe-id"`
			CVEID          []string `json:"cve-id"`
			CVSSMetrics    string   `json:"cvss-metrics"`
			CVSSScore      float64  `json:"cvss-score"`
			EPSSScore      float64  `json:"epss-score"`
			EPSSPercentile float64  `json:"epss-percentile"`
		} `json:"classification"`
	} `json:"info"`
	Type             string   `json:"type"`
	Host             string   `json:"host"`
	IP               string   `json:"ip"`
	MatchedAt        string   `json:"matched-at"`
	MatcherName      string   `json:"matcher-name"`
	ExtractedResults []string `json:"extracted-results"`
	CurlCommand      string   `json:"curl-command"`
	Request          string   `json:"request"`
	Response         string   `json:"response"`
	Timestamp        string   `json:"timestamp"`
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

	count, errs := 0, 0
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

		d := map[string]any{}
		if len(result.Info.Author) > 0 {
			d["author"] = result.Info.Author
		}
		if len(result.Info.Tags) > 0 {
			d["tags"] = result.Info.Tags
		}
		if len(result.Info.Reference) > 0 {
			d["reference"] = result.Info.Reference
		}
		if len(result.Info.Classification.CVEID) > 0 {
			d["cve_id"] = result.Info.Classification.CVEID
		}
		if result.Info.Classification.CVSSMetrics != "" {
			d["cvss_metrics"] = result.Info.Classification.CVSSMetrics
		}
		if result.Info.Classification.CVSSScore > 0 {
			d["cvss_score"] = result.Info.Classification.CVSSScore
		}
		if result.Info.Classification.EPSSScore > 0 {
			d["epss_score"] = result.Info.Classification.EPSSScore
		}
		if result.Info.Classification.EPSSPercentile > 0 {
			d["epss_percentile"] = result.Info.Classification.EPSSPercentile
		}
		if rem := strings.TrimSpace(result.Info.Remediation); rem != "" {
			d["remediation"] = rem
		}
		if result.MatcherName != "" {
			d["matcher_name"] = result.MatcherName
		}
		if result.Type != "" {
			d["type"] = result.Type
		}
		if result.Host != "" {
			d["host"] = result.Host
		}
		if result.IP != "" {
			d["ip"] = result.IP
		}
		if len(result.ExtractedResults) > 0 {
			d["extracted_results"] = result.ExtractedResults
		}
		if result.CurlCommand != "" {
			d["curl_command"] = result.CurlCommand
		}
		if result.Request != "" {
			d["request"] = truncate(result.Request, maxDetailBytes)
		}
		if result.Response != "" {
			d["response"] = truncate(result.Response, maxDetailBytes)
		}
		finding.Details = marshalDetails(d)

		if err := o.store.InsertFinding(ctx, finding); err != nil {
			log.Printf("orchestrator: insert nuclei finding failed (job=%s url=%s): %v", jobID, result.MatchedAt, err)
			errs++
		} else {
			count++
		}
	}
	log.Printf("orchestrator: stored %d Nuclei findings for job %s (%d insert errors)", count, jobID, errs)
	if errs > 0 {
		return count, fmt.Errorf("%d of %d Nuclei findings failed to insert", errs, count+errs)
	}
	return count, nil
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func marshalDetails(d map[string]any) json.RawMessage {
	if len(d) == 0 {
		return nil
	}
	b, err := json.Marshal(d)
	if err != nil {
		return nil
	}
	return json.RawMessage(b)
}

func copyMap(m map[string]any) map[string]any {
	out := make(map[string]any, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max] + "…"
}
