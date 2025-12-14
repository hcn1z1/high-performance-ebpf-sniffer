package main

import (
	"context"
	"crypto/sha256"
	"encoding/csv"
	"fmt"
	"hash/fnv"
	"io"
	"log"
	"math"
	"os"
	"time"

	pb "github.com/qdrant/go-client/qdrant"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

type VectorDB struct {
	client     pb.CollectionsClient
	points     pb.PointsClient
	collection string
	knownDB    map[string]KnownJA4
	enricher   *Enricher
}

type KnownJA4 struct {
	JA4         string `json:"ja4"`
	Description string `json:"description"`
	RiskLevel   string `json:"risk_level"`
}

const VectorSize = 512

func NewVectorDB(addr string) (*VectorDB, error) {
	conn, err := grpc.Dial(addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return nil, fmt.Errorf("did not connect: %v", err)
	}

	vdb := &VectorDB{
		client:     pb.NewCollectionsClient(conn),
		points:     pb.NewPointsClient(conn),
		collection: "tls_fingerprints_v2",
		knownDB:    make(map[string]KnownJA4),
		enricher:   NewEnricher(),
	}

	// Load known database
	if err := vdb.loadKnownDB("ja4plus-mapping.csv"); err != nil {
		log.Printf("Warning: Failed to load known DB: %v", err)
	} else {
		log.Printf("Loaded %d known JA4 signatures", len(vdb.knownDB))
	}

	// Initialize collection
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Check if collection exists
	existsResp, err := vdb.client.CollectionExists(ctx, &pb.CollectionExistsRequest{CollectionName: vdb.collection})

	if err != nil || (existsResp != nil && !existsResp.Result.Exists) {
		log.Printf("Collection not found or error checking (err=%v), creating %s...", err, vdb.collection)
		_, err = vdb.client.Create(ctx, &pb.CreateCollection{
			CollectionName: vdb.collection,
			VectorsConfig: &pb.VectorsConfig{Config: &pb.VectorsConfig_Params{
				Params: &pb.VectorParams{
					Size:     VectorSize,
					Distance: pb.Distance_Cosine,
				},
			}},
		})
		if err != nil {
			return nil, fmt.Errorf("failed to create collection: %v", err)
		}
	}

	return vdb, nil
}

func (v *VectorDB) loadKnownDB(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()

	r := csv.NewReader(f)

	// Read Header
	header, err := r.Read()
	if err != nil { return err }

	// Map header columns to indices
	colMap := make(map[string]int)
	for i, col := range header {
		colMap[col] = i
	}

	// Required columns
	ja4Idx, ok1 := colMap["ja4"]
	appIdx, ok2 := colMap["Application"]

	if !ok1 || !ok2 {
		return fmt.Errorf("invalid CSV format: missing ja4 or Application column")
	}

	for {
		record, err := r.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			log.Printf("Error reading CSV row: %v", err)
			continue
		}

		if len(record) <= ja4Idx || len(record) <= appIdx {
			continue
		}

		ja4 := record[ja4Idx]
		if ja4 == "" {
			continue
		}

		desc := record[appIdx]
		// Add Library or OS if available
		if idx, ok := colMap["Library"]; ok && len(record) > idx && record[idx] != "" {
			desc += " (" + record[idx] + ")"
		}
		if idx, ok := colMap["OS"]; ok && len(record) > idx && record[idx] != "" {
			desc += " on " + record[idx]
		}
		if idx, ok := colMap["Notes"]; ok && len(record) > idx && record[idx] != "" {
			desc += " - " + record[idx]
		}

		v.knownDB[ja4] = KnownJA4{
			JA4: ja4,
			Description: desc,
			RiskLevel: "info", // Default to info/known good
		}
	}
	return nil
}

// simpleJA4Embedding converts a JA4 string into a deterministic float vector
// using Bag-of-Trigrams with L2 normalization for cosine similarity.
func simpleJA4Embedding(ja4 string) []float32 {
	vec := make([]float32, VectorSize)
	if len(ja4) < 3 {
		return vec
	}

	// Bag of Trigrams
	for i := 0; i < len(ja4)-2; i++ {
		trigram := ja4[i : i+3]
		// Deterministic hash for index
		h := fnv.New32a()
		h.Write([]byte(trigram))
		idx := h.Sum32() % uint32(VectorSize)
		vec[idx]++
	}

	// L2 Normalization
	var sumSq float64
	for _, v := range vec {
		sumSq += float64(v * v)
	}
	magnitude := float32(math.Sqrt(sumSq))

	if magnitude > 0 {
		for i := range vec {
			vec[i] /= magnitude
		}
	}
	return vec
}

// FindClosest finds the nearest neighbor in Qdrant
func (v *VectorDB) FindClosest(ctx context.Context, vector []float32) (string, float32, string) {
	searchResult, err := v.points.Search(ctx, &pb.SearchPoints{
		CollectionName: v.collection,
		Vector:         vector,
		Limit:          1,
		WithPayload:    &pb.WithPayloadSelector{SelectorOptions: &pb.WithPayloadSelector_Enable{Enable: true}},
	})

	if err != nil || len(searchResult.Result) == 0 {
		return "", 0.0, ""
	}

	match := searchResult.Result[0]
	desc := "Unknown"
	if match.Payload != nil {
		if d, ok := match.Payload["description"]; ok {
			desc = d.GetStringValue()
		}
	}
	return match.Id.GetUuid(), match.Score, desc
}

func (v *VectorDB) SaveAndVerify(res AnalysisResult) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	vector := simpleJA4Embedding(res.JA4)

	// 1. Exact Match Verification (Local & External)
	description := "Unknown"
	risk := "unknown"

	// Local
	if known, ok := v.knownDB[res.JA4]; ok {
		log.Printf("ALERT: Detected Known JA4! Risk: %s, Desc: %s, JA4: %s", known.RiskLevel, known.Description, res.JA4)
		description = known.Description
		risk = known.RiskLevel
	}

	// External
	enrichmentResults := v.enricher.Enrich(res.JA4)
	for _, e := range enrichmentResults {
		log.Printf("ENRICHMENT: [%s] %s (Malicious: %v)", e.Source, e.Description, e.Malicious)
		if e.Malicious {
			risk = "high"
			description = fmt.Sprintf("%s | %s: %s", description, e.Source, e.Description)
		} else {
			description = fmt.Sprintf("%s | %s: %s", description, e.Source, e.Description)
		}
	}

	// 2. Similarity Search (Nearest Neighbor)
	// Only perform if we don't have a strong match yet or for additional context
	if risk == "unknown" || risk == "info" {
		_, score, similarDesc := v.FindClosest(ctx, vector)
		// Threshold: 0.85 (Cosine similarity) for high-dimensional N-Grams
		if score > 0.5 && score < 0.9999 { // < 0.9999 means not self/exact match usually
			log.Printf("SIMILARITY ALERT: Traffic is %.2f%% similar to: %s", score*100, similarDesc)
			description = fmt.Sprintf("%s (Similar to: %s - %.0f%%)", description, similarDesc, score*100)
			risk = "suspicious" // Upgrade risk for high similarity
		}
	}

	// Always Log Info for Visibility
	log.Printf("INFO: Processed JA4: %s | Risk: %s | Desc: %s", res.JA4, risk, description)

	// Save to Qdrant
	// Point ID: Use Hash of JA4 or random UUID?
	// To avoid duplicates, we might want to use the hash as ID, but Qdrant requires UUID or uint64.
	// Let's generate a UUID from the JA4 string (first 16 bytes of SHA256).
	h := sha256.Sum256([]byte(res.JA4))
	// Construct UUID string
	uuidStr := fmt.Sprintf("%x-%x-%x-%x-%x", h[0:4], h[4:6], h[6:8], h[8:10], h[10:16])

	// Prepare Payload
	payload := map[string]*pb.Value{
		"ja4":         {Kind: &pb.Value_StringValue{StringValue: res.JA4}},
		"src_ip":      {Kind: &pb.Value_StringValue{StringValue: res.SrcIP}},
		"dst_ip":      {Kind: &pb.Value_StringValue{StringValue: res.DstIP}},
		"timestamp":   {Kind: &pb.Value_StringValue{StringValue: res.Timestamp.Format(time.RFC3339)}},
		"description": {Kind: &pb.Value_StringValue{StringValue: description}},
		"risk_level":  {Kind: &pb.Value_StringValue{StringValue: risk}},
	}

	_, err := v.points.Upsert(ctx, &pb.UpsertPoints{
		CollectionName: v.collection,
		Points: []*pb.PointStruct{
			{
				Id: &pb.PointId{PointIdOptions: &pb.PointId_Uuid{Uuid: uuidStr}},
				Vectors: &pb.Vectors{VectorsOptions: &pb.Vectors_Vector{Vector: &pb.Vector{Data: vector}}},
				Payload: payload,
			},
		},
	})
	if err != nil {
		log.Printf("Error saving to Qdrant: %v", err)
	}
}

// GetInfo returns details if the hash exists in Qdrant or Known DB
func (v *VectorDB) GetInfo(ja4 string) map[string]interface{} {
	info := make(map[string]interface{})

	// Check Known DB
	if known, ok := v.knownDB[ja4]; ok {
		info["known_db"] = known
	}

	// Query Qdrant
	// We use the same deterministic UUID generation
	h := sha256.Sum256([]byte(ja4))
	uuidStr := fmt.Sprintf("%x-%x-%x-%x-%x", h[0:4], h[4:6], h[6:8], h[8:10], h[10:16])

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	resp, err := v.points.Get(ctx, &pb.GetPoints{
		CollectionName: v.collection,
		Ids: []*pb.PointId{{PointIdOptions: &pb.PointId_Uuid{Uuid: uuidStr}}},
	})

	if err == nil && len(resp.Result) > 0 {
		point := resp.Result[0]
		info["stored_data"] = point.Payload
		info["last_seen"] = true
	} else {
		info["last_seen"] = false
	}

	return info
}
