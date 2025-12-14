package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"sync"
	"time"
)

// EnrichmentResult holds data from external sources
type EnrichmentResult struct {
	Source      string                 `json:"source"`
	Malicious   bool                   `json:"malicious"`
	Description string                 `json:"description"`
	Details     map[string]interface{} `json:"details,omitempty"`
}

// Enricher handles external API lookups with caching
type Enricher struct {
	cache      map[string]*EnrichmentEntry
	mu         sync.RWMutex
	httpClient *http.Client

	// API Keys
	ThreatFoxKey string
	GreyNoiseKey string
	VTKey        string
}

type EnrichmentEntry struct {
	Data      []EnrichmentResult
	Timestamp time.Time
}

const CacheTTL = 1 * time.Hour

func NewEnricher() *Enricher {
	return &Enricher{
		cache: make(map[string]*EnrichmentEntry),
		httpClient: &http.Client{
			Timeout: 5 * time.Second,
		},
		ThreatFoxKey: os.Getenv("THREATFOX_API_KEY"),
		GreyNoiseKey: os.Getenv("GREYNOISE_API_KEY"),
		VTKey:        os.Getenv("VT_API_KEY"),
	}
}

// Enrich checks cache or queries APIs. Returns a list of findings.
// This is non-blocking to the main loop if called in a goroutine,
// but here we might want to wait if it's a new hash to log immediate alerts.
func (e *Enricher) Enrich(ja4 string) []EnrichmentResult {
	e.mu.RLock()
	entry, exists := e.cache[ja4]
	e.mu.RUnlock()

	if exists && time.Since(entry.Timestamp) < CacheTTL {
		return entry.Data
	}

	// Cache miss or expired: Query APIs
	var results []EnrichmentResult
	var wg sync.WaitGroup
	var resMu sync.Mutex

	// Helper to append results concurrently
	addRes := func(r []EnrichmentResult) {
		resMu.Lock()
		results = append(results, r...)
		resMu.Unlock()
	}

	// 1. ThreatFox
	if e.ThreatFoxKey != "" {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if res := e.checkThreatFox(ja4); len(res) > 0 {
				addRes(res)
			}
		}()
	}

	// 2. GreyNoise
	if e.GreyNoiseKey != "" {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if res := e.checkGreyNoise(ja4); len(res) > 0 {
				addRes(res)
			}
		}()
	}

	// 3. VirusTotal
	if e.VTKey != "" {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if res := e.checkVirusTotal(ja4); len(res) > 0 {
				addRes(res)
			}
		}()
	}

	wg.Wait()

	// Update Cache
	e.mu.Lock()
	e.cache[ja4] = &EnrichmentEntry{
		Data:      results,
		Timestamp: time.Now(),
	}
	e.mu.Unlock()

	return results
}

// --- API Implementations ---

// ThreatFox
func (e *Enricher) checkThreatFox(ja4 string) []EnrichmentResult {
	url := "https://threatfox-api.abuse.ch/api/v1/"
	payload := map[string]interface{}{
		"query":       "search_ioc",
		"search_term": ja4,
	}
	body, _ := json.Marshal(payload)

	req, err := http.NewRequest("POST", url, bytes.NewBuffer(body))
	if err != nil { return nil }
	req.Header.Set("Content-Type", "application/json")
	// ThreatFox requires Auth-Key for search_ioc
	req.Header.Set("Auth-Key", e.ThreatFoxKey)

	resp, err := e.httpClient.Do(req)
	if err != nil {
		log.Printf("ThreatFox API error: %v", err)
		return nil
	}
	defer resp.Body.Close()

	var result struct {
		QueryStatus string `json:"query_status"`
		Data        []struct {
			ThreatType string `json:"threat_type"`
			Malware    string `json:"malware_printable"`
		} `json:"data"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil { return nil }

	if result.QueryStatus == "ok" && len(result.Data) > 0 {
		var out []EnrichmentResult
		for _, item := range result.Data {
			out = append(out, EnrichmentResult{
				Source:      "ThreatFox",
				Malicious:   true,
				Description: fmt.Sprintf("Malware: %s (%s)", item.Malware, item.ThreatType),
			})
		}
		return out
	}
	return nil
}

// GreyNoise (Community/Enterprise GNQL)
func (e *Enricher) checkGreyNoise(ja4 string) []EnrichmentResult {
	// Using Enterprise GNQL search as Community API doesn't support JA4 lookup directly usually
	// URL: https://api.greynoise.io/v2/experimental/gnql?query=fingerprint.ja4:<ja4>
	// Note: This endpoint might vary based on subscription. Using generic approach.

	url := fmt.Sprintf("https://api.greynoise.io/v2/experimental/gnql?query=fingerprint.ja4:%s", ja4)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil { return nil }
	req.Header.Set("key", e.GreyNoiseKey)
	req.Header.Set("Accept", "application/json")

	resp, err := e.httpClient.Do(req)
	if err != nil { return nil }
	defer resp.Body.Close()

	if resp.StatusCode == 200 {
		var result struct {
			Count int `json:"count"`
			Data []struct {
				IP string `json:"ip"`
				Classification struct {
					Category string `json:"category"` // "malicious" or "benign"
				} `json:"classification"`
			} `json:"data"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&result); err == nil && result.Count > 0 {
			category := "unknown"
			if len(result.Data) > 0 {
				category = result.Data[0].Classification.Category
			}
			return []EnrichmentResult{{
				Source:      "GreyNoise",
				Malicious:   category == "malicious",
				Description: fmt.Sprintf("Seen on %d IPs (Category: %s)", result.Count, category),
			}}
		}
	}
	return nil
}

// VirusTotal
func (e *Enricher) checkVirusTotal(ja4 string) []EnrichmentResult {
	// Search query: behavior_network:<ja4>
	url := fmt.Sprintf("https://www.virustotal.com/api/v3/search?query=behavior_network:%s", ja4)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil { return nil }
	req.Header.Set("x-apikey", e.VTKey)

	resp, err := e.httpClient.Do(req)
	if err != nil { return nil }
	defer resp.Body.Close()

	if resp.StatusCode == 200 {
		var result struct {
			Data []struct {
				Attributes struct {
					MeaningfulName string `json:"meaningful_name"`
					Stats struct {
						Malicious int `json:"malicious"`
					} `json:"last_analysis_stats"`
				} `json:"attributes"`
			} `json:"data"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&result); err == nil && len(result.Data) > 0 {
			maliciousCount := 0
			name := "Unknown"
			for _, item := range result.Data {
				maliciousCount += item.Attributes.Stats.Malicious
				if item.Attributes.MeaningfulName != "" {
					name = item.Attributes.MeaningfulName
				}
			}
			if maliciousCount > 0 {
				return []EnrichmentResult{{
					Source:      "VirusTotal",
					Malicious:   true,
					Description: fmt.Sprintf("Associated with %s (Malicious hits: %d)", name, maliciousCount),
				}}
			}
		}
	}
	return nil
}

