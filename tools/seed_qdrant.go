package main

import (
	"context"
	"crypto/sha256"
	"encoding/csv"
	"flag"
	"fmt"
	"hash/fnv"
	"io"
	"log"
	"math"
	"os"
	"sort"
	"strings"

	pb "github.com/qdrant/go-client/qdrant"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

const VectorSize = 512
const BatchSize = 100

// simpleJA4Embedding converts a JA4 string into a deterministic float vector
// Must match the logic in sniffer/vector_db.go
// Uses Bag-of-Trigrams with L2 normalization.
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

// generateID creates a deterministic UUID from the JA4 string
// Must match sniffer/vector_db.go
func generateID(ja4 string) string {
	h := sha256.Sum256([]byte(ja4))
	return fmt.Sprintf("%x-%x-%x-%x-%x", h[0:4], h[4:6], h[6:8], h[8:10], h[10:16])
}

type AggregatedRecord struct {
	JA4          string
	Descriptions map[string]bool
	Sources      map[string]bool
	MaxRisk      string
}

func getRiskScore(risk string) int {
	r := strings.ToLower(risk)
	if strings.Contains(r, "high") || strings.Contains(r, "malicious") {
		return 3
	}
	if strings.Contains(r, "suspicious") {
		return 2
	}
	return 1 // Safe, Info, Unknown
}

func updateRisk(current, newRisk string) string {
	if getRiskScore(newRisk) > getRiskScore(current) {
		return newRisk
	}
	return current
}

func truncateDescription(desc string) string {
	if len(desc) > 3000 {
		return desc[:2997] + "..."
	}
	return desc
}

func main() {
	csvPath := flag.String("csv", "tools/data/combined_ja4_db.csv", "Path to the CSV file")
	qdrantAddr := flag.String("addr", "localhost:6334", "Qdrant gRPC address")
	collection := flag.String("coll", "tls_fingerprints_v2", "Collection name")
	flag.Parse()

	log.Printf("Connecting to Qdrant at %s...", *qdrantAddr)
	conn, err := grpc.Dial(*qdrantAddr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		log.Fatalf("Did not connect: %v", err)
	}
	defer conn.Close()

	pointsClient := pb.NewPointsClient(conn)
	collectionsClient := pb.NewCollectionsClient(conn)

	ctx := context.Background()

	// Ensure collection exists
	existsResp, err := collectionsClient.CollectionExists(ctx, &pb.CollectionExistsRequest{CollectionName: *collection})

	if err != nil || (existsResp != nil && !existsResp.Result.Exists) {
		log.Printf("Collection '%s' not found (or error), attempting to create...", *collection)
		// We'll try to create it, ignoring errors if it already exists (race condition)
		_, _ = collectionsClient.Create(ctx, &pb.CreateCollection{
			CollectionName: *collection,
			VectorsConfig: &pb.VectorsConfig{Config: &pb.VectorsConfig_Params{
				Params: &pb.VectorParams{
					Size:     VectorSize,
					Distance: pb.Distance_Cosine,
				},
			}},
		})
	}

	log.Printf("Reading CSV: %s", *csvPath)
	f, err := os.Open(*csvPath)
	if err != nil {
		log.Fatalf("Failed to open CSV: %v", err)
	}
	defer f.Close()

	reader := csv.NewReader(f)

	// Skip header
	_, err = reader.Read()
	if err != nil {
		log.Fatalf("Failed to read header: %v", err)
	}

	// Aggregation Step
	aggregated := make(map[string]*AggregatedRecord)

	for {
		record, err := reader.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			continue
		}

		// Format: ja4,description,source,risk_level
		if len(record) < 4 {
			continue
		}
		ja4 := record[0]
		desc := record[1]
		source := record[2]
		risk := record[3]

		if ja4 == "" {
			continue
		}

		if _, ok := aggregated[ja4]; !ok {
			aggregated[ja4] = &AggregatedRecord{
				JA4:          ja4,
				Descriptions: make(map[string]bool),
				Sources:      make(map[string]bool),
				MaxRisk:      "info",
			}
		}

		entry := aggregated[ja4]
		if desc != "" {
			entry.Descriptions[desc] = true
		}
		if source != "" {
			entry.Sources[source] = true
		}
		entry.MaxRisk = updateRisk(entry.MaxRisk, risk)
	}

	var points []*pb.PointStruct
	count := 0
	total := 0

	log.Printf("Aggregated into %d unique fingerprints. Generating vectors...", len(aggregated))

	for _, entry := range aggregated {
		// Combine Descriptions
		descList := make([]string, 0, len(entry.Descriptions))
		for d := range entry.Descriptions {
			descList = append(descList, d)
		}
		sort.Strings(descList) // deterministic order
		fullDesc := strings.Join(descList, " | ")
		fullDesc = truncateDescription(fullDesc)

		// Combine Sources
		sourceList := make([]string, 0, len(entry.Sources))
		for s := range entry.Sources {
			sourceList = append(sourceList, s)
		}
		sort.Strings(sourceList)
		fullSource := strings.Join(sourceList, " | ")

		vector := simpleJA4Embedding(entry.JA4)
		uuidStr := generateID(entry.JA4)

		payload := map[string]*pb.Value{
			"ja4":         {Kind: &pb.Value_StringValue{StringValue: entry.JA4}},
			"description": {Kind: &pb.Value_StringValue{StringValue: fullDesc}},
			"source":      {Kind: &pb.Value_StringValue{StringValue: fullSource}},
			"risk_level":  {Kind: &pb.Value_StringValue{StringValue: entry.MaxRisk}},
			"type":        {Kind: &pb.Value_StringValue{StringValue: "known_signature"}},
		}

		points = append(points, &pb.PointStruct{
			Id:      &pb.PointId{PointIdOptions: &pb.PointId_Uuid{Uuid: uuidStr}},
			Vectors: &pb.Vectors{VectorsOptions: &pb.Vectors_Vector{Vector: &pb.Vector{Data: vector}}},
			Payload: payload,
		})
		count++

		if count >= BatchSize {
			upsert(ctx, pointsClient, *collection, points)
			total += count
			count = 0
			points = nil
			fmt.Printf("\rSeeded %d records...", total)
		}
	}

	if len(points) > 0 {
		upsert(ctx, pointsClient, *collection, points)
		total += len(points)
	}

	fmt.Printf("\nDone! Seeded %d total records.\n", total)
}

func upsert(ctx context.Context, client pb.PointsClient, collection string, points []*pb.PointStruct) {
	_, err := client.Upsert(ctx, &pb.UpsertPoints{
		CollectionName: collection,
		Points:         points,
	})
	if err != nil {
		log.Printf("Error upserting batch: %v", err)
	}
}
