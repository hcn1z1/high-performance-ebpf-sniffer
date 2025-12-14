package main

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"math"
	"net"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/redis/go-redis/v9"
)

type PacketMetadata struct {
	Len        uint32
	CaptureLen uint32
	EventType  uint32
	SrcIP      uint32
}

const (
	EVENT_TYPE_CAPTURE = 0
	EVENT_TYPE_ALERT   = 1
)

type AnalysisResult struct {
	Timestamp       time.Time              `json:"timestamp"`
	SrcIP           string                 `json:"src_ip"`
	DstIP           string                 `json:"dst_ip"`
	SrcPort         uint16                 `json:"src_port"`
	DstPort         uint16                 `json:"dst_port"`
	TCPFeatures     map[string]interface{} `json:"tcp_features"`
	JA4             string                 `json:"ja4"`
	ClosestMatch    string                 `json:"closest_match,omitempty"`
	SimilarityScore float32                `json:"similarity_score,omitempty"`
	MatchDesc       string                 `json:"match_desc,omitempty"`
}

type DDoSAlert struct {
	Timestamp time.Time `json:"timestamp"`
	SrcIP     string    `json:"src_ip"`
	Event     string    `json:"event"`
}

// FlowMetrics must match the C struct layout
type FlowMetrics struct {
	FirstSeen    uint64
	LastSeen     uint64
	SumIATUs     uint64
	SumIATSqUs   uint64
	MinIATUs     uint64
	MaxIATUs     uint64
	PktCount     uint64
	TotalBytes   uint64
	SumPktLen    uint64
	SumPktLenSq  uint64
	MaxPktLen    uint64
	CntSYN       uint64
	CntACK       uint64
	CntRST       uint64
	CntFIN       uint64
	SumWinSize   uint64
	SumTTL       uint64
}

type DDoSMetric struct {
	Timestamp    time.Time `json:"timestamp"`
	SrcIP        string    `json:"src_ip"`
	FlowIATMean  float64   `json:"flow_iat_mean"`
	FlowIATStd   float64   `json:"flow_iat_std"`
	FlowIATMin   uint64    `json:"flow_iat_min"`
	FlowIATMax   uint64    `json:"flow_iat_max"`
	FlowDuration float64   `json:"flow_duration"` // seconds
	PacketRate   float64   `json:"packet_rate"`
	ByteRate     float64   `json:"byte_rate"`
	PktLenMean   float64   `json:"pkt_len_mean"`
	PktLenStd    float64   `json:"pkt_len_std"`
	PktLenMax    uint64    `json:"pkt_len_max"`
	BytesIn      uint64    `json:"bytes_in"`
	BytesOut     uint64    `json:"bytes_out"` // 0 for now
	SYNCount     uint64    `json:"syn_count"`
	ACKCount     uint64    `json:"ack_count"`
	RSTCount     uint64    `json:"rst_count"`
	FINCount     uint64    `json:"fin_count"`
	SYNACKRatio  float64   `json:"syn_ack_ratio"`
	TTLMean      float64   `json:"ttl_mean"`
	WinSizeMean  float64   `json:"win_size_mean"`
}

func main() {
	spec, err := ebpf.LoadCollectionSpec("bpf_program.o")
	if err != nil {
		log.Fatalf("Failed to load BPF spec: %v", err)
	}

	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		log.Fatalf("Failed to create BPF collection: %v", err)
	}
	defer coll.Close()

	// Configuration: DDoS Threshold
	ddosThresholdStr := os.Getenv("DDOS_SYN_THRESHOLD")
	ddosThreshold := 100
	if ddosThresholdStr != "" {
		if val, err := strconv.Atoi(ddosThresholdStr); err == nil {
			ddosThreshold = val
		}
	}

	// Update config map
	configMap := coll.Maps["config_map"]
	if configMap != nil {
		key := uint32(0)
		val := uint32(ddosThreshold)
		if err := configMap.Update(key, val, ebpf.UpdateAny); err != nil {
			log.Printf("Failed to update DDoS threshold map: %v", err)
		} else {
			log.Printf("DDoS SYN Threshold set to %d/sec", ddosThreshold)
		}
	}

	interfaceName := os.Getenv("INTERFACE")
	if interfaceName == "" {
		interfaceName = "eth0"
	}

	iface, err := net.InterfaceByName(interfaceName)
	if err != nil {
		log.Fatalf("Failed to lookup interface %s: %v", interfaceName, err)
	}

	// Attach XDP
	xdpLink, err := link.AttachXDP(link.XDPOptions{
		Program:   coll.Programs["packet_monitor"],
		Interface: iface.Index,
		Flags:     link.XDPDriverMode, // Try Native Mode first
	})
	if err != nil {
		log.Printf("Failed to attach XDP in Driver Mode: %v. Retrying in Generic Mode...", err)
		xdpLink, err = link.AttachXDP(link.XDPOptions{
			Program:   coll.Programs["packet_monitor"],
			Interface: iface.Index,
			Flags:     link.XDPGenericMode,
		})
		if err != nil {
			log.Fatalf("Failed to attach XDP: %v", err)
		}
	}
	defer xdpLink.Close()

	rd, err := perf.NewReader(coll.Maps["events"], 4096)
	if err != nil {
		log.Fatalf("Failed to create perf reader: %v", err)
	}
	defer rd.Close()

	redisAddr := os.Getenv("REDIS_ADDR")
	if redisAddr == "" {
		redisAddr = "localhost:16379"
	}

	qdrantAddr := os.Getenv("QDRANT_ADDR")
	if qdrantAddr == "" {
		qdrantAddr = "localhost:6334"
	}

	// Initialize Vector DB
	vdb, err := NewVectorDB(qdrantAddr)
	if err != nil {
		log.Printf("Warning: Failed to connect to Qdrant at %s: %v", qdrantAddr, err)
	} else {
		log.Printf("Connected to Qdrant at %s", qdrantAddr)
	}

	// Initialize Redis
	rdb := redis.NewClient(&redis.Options{
		Addr: redisAddr,
	})

	// Fan-out architecture
	pubChan := make(chan AnalysisResult, 1000)
	redisChan := make(chan AnalysisResult, 1000)
	qdrantChan := make(chan AnalysisResult, 1000)
	alertChan := make(chan DDoSAlert, 100)

	go redisPublisher(rdb, redisChan)
	go vectorDBWorker(vdb, qdrantChan)
	go alertPublisher(rdb, alertChan)

	// Start Flow Metrics Monitor
	go metricsMonitor(coll, rdb)

	// Broadcaster
	go func() {
		for msg := range pubChan {
			// Non-blocking fan-out
			select {
			case redisChan <- msg:
			default:
			}
			select {
			case qdrantChan <- msg:
			default:
			}
		}
	}()

	fmt.Printf("Sniffer started on %s (XDP)...\n", interfaceName)
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	go func() { <-sig; rd.Close() }()

	for {
		record, err := rd.Read()
		if err != nil {
			if errors.Is(err, perf.ErrClosed) {
				return
			}
			log.Printf("Perf read error: %v", err)
			continue
		}

		if len(record.RawSample) < 16 { // Updated struct size check (4 fields * 4 bytes)
			continue
		}
		var meta PacketMetadata
		meta.Len = binary.LittleEndian.Uint32(record.RawSample[0:4])
		meta.CaptureLen = binary.LittleEndian.Uint32(record.RawSample[4:8])
		meta.EventType = binary.LittleEndian.Uint32(record.RawSample[8:12])
		meta.SrcIP = binary.LittleEndian.Uint32(record.RawSample[12:16])

		if meta.EventType == EVENT_TYPE_ALERT {
			// Convert uint32 IP to string
			ip := make(net.IP, 4)
			binary.LittleEndian.PutUint32(ip, meta.SrcIP)

			alert := DDoSAlert{
				Timestamp: time.Now(),
				SrcIP:     ip.String(),
				Event:     "syn_flood_detected",
			}
			log.Printf("ALERT: DDoS Detected from %s", alert.SrcIP)
			select {
			case alertChan <- alert:
			default:
			}
			continue
		}

		// EVENT_TYPE_CAPTURE
		packetData := record.RawSample[16:] // Adjusted offset
		if len(packetData) > int(meta.CaptureLen) {
			packetData = packetData[:meta.CaptureLen]
		}

		packet := gopacket.NewPacket(packetData, layers.LayerTypeEthernet, gopacket.Default)
		if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
			tcp, _ := tcpLayer.(*layers.TCP)
			if len(tcp.Payload) > 0 {
				ja4Str, err := ParseJA4(tcp.Payload)
				if err == nil {
					log.Printf("DEBUG: Found JA4: %s", ja4Str)
					ipLayer := packet.Layer(layers.LayerTypeIPv4)
					var srcIP, dstIP string
					if ipLayer != nil {
						ip, _ := ipLayer.(*layers.IPv4)
						srcIP, dstIP = ip.SrcIP.String(), ip.DstIP.String()
					}

					res := AnalysisResult{
						Timestamp:   time.Now(),
						SrcIP:       srcIP,
						DstIP:       dstIP,
						SrcPort:     uint16(tcp.SrcPort),
						DstPort:     uint16(tcp.DstPort),
						TCPFeatures: map[string]interface{}{"window": tcp.Window, "seq": tcp.Seq, "ack": tcp.Ack},
						JA4:         ja4Str,
					}

					select {
					case pubChan <- res:
					default:
					}
				}
			}
		}
	}
}

func metricsMonitor(coll *ebpf.Collection, rdb *redis.Client) {
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	metricsMap := coll.Maps["flow_metrics_map"]
	if metricsMap == nil {
		log.Printf("Warning: flow_metrics_map not found in BPF collection")
		return
	}

	for range ticker.C {
		var key uint32
		var values []FlowMetrics // Must use slice for PERCPU map

		iter := metricsMap.Iterate()
		pipe := rdb.Pipeline()
		ctx := context.Background()
		count := 0

		// Map cleanup state
		var toDelete []uint32
		var maxLastSeen uint64

		for iter.Next(&key, &values) {
			// Aggregate
			var agg FlowMetrics
			agg.MinIATUs = ^uint64(0)

			for _, v := range values {
				if v.PktCount == 0 {
					continue
				}
				if v.FirstSeen < agg.FirstSeen || agg.FirstSeen == 0 {
					agg.FirstSeen = v.FirstSeen
				}
				if v.LastSeen > agg.LastSeen {
					agg.LastSeen = v.LastSeen
				}
				agg.SumIATUs += v.SumIATUs
				agg.SumIATSqUs += v.SumIATSqUs
				if v.MinIATUs < agg.MinIATUs {
					agg.MinIATUs = v.MinIATUs
				}
				if v.MaxIATUs > agg.MaxIATUs {
					agg.MaxIATUs = v.MaxIATUs
				}
				agg.PktCount += v.PktCount
				agg.TotalBytes += v.TotalBytes
				agg.SumPktLen += v.SumPktLen
				agg.SumPktLenSq += v.SumPktLenSq
				if v.MaxPktLen > agg.MaxPktLen {
					agg.MaxPktLen = v.MaxPktLen
				}
				agg.CntSYN += v.CntSYN
				agg.CntACK += v.CntACK
				agg.CntRST += v.CntRST
				agg.CntFIN += v.CntFIN
				agg.SumWinSize += v.SumWinSize
				agg.SumTTL += v.SumTTL
			}

			if agg.PktCount == 0 {
				continue
			}

			// Math
			var iatMean float64
			var iatStd float64
			if agg.PktCount > 0 {
				iatMean = float64(agg.SumIATUs) / float64(agg.PktCount)
				// Variance = E[X^2] - (E[X])^2
				meanSq := float64(agg.SumIATSqUs) / float64(agg.PktCount)
				variance := meanSq - (iatMean * iatMean)
				if variance > 0 {
					iatStd = math.Sqrt(variance)
				}
			}

			// Duration (ns to s)
			duration := float64(agg.LastSeen-agg.FirstSeen) / 1e9

			// Rates
			var pktRate, byteRate float64
			if duration > 0 {
				pktRate = float64(agg.PktCount) / duration
				byteRate = float64(agg.TotalBytes) / duration
			}

			// Pkt Len Stats
			var lenMean, lenStd float64
			if agg.PktCount > 0 {
				lenMean = float64(agg.SumPktLen) / float64(agg.PktCount)
				lenMeanSq := float64(agg.SumPktLenSq) / float64(agg.PktCount)
				lenVar := lenMeanSq - (lenMean * lenMean)
				if lenVar > 0 {
					lenStd = math.Sqrt(lenVar)
				}
			}

			// Track maxLastSeen for eviction
			if agg.LastSeen > maxLastSeen {
				maxLastSeen = agg.LastSeen
			}

			// Eviction Check: If flow is older than 30s relative to freshest packet
			// 30 seconds = 30,000,000,000 ns
			// We only check if maxLastSeen is established to avoid deleting on startup
			if maxLastSeen > 30000000000 && agg.LastSeen < maxLastSeen-30000000000 {
				toDelete = append(toDelete, key)
				// Skip reporting stale metrics?
				// Let's report one last time, so we continue.
			}

			// Ratio
			// Formula: cnt_syn / (cnt_ack + 1)
			synAckRatio := float64(agg.CntSYN) / (float64(agg.CntACK) + 1.0)

			// Construct Metric
			ip := make(net.IP, 4)
			binary.LittleEndian.PutUint32(ip, key)

			m := DDoSMetric{
				Timestamp:    time.Now(),
				SrcIP:        ip.String(),
				FlowIATMean:  iatMean,
				FlowIATStd:   iatStd,
				FlowIATMin:   agg.MinIATUs,
				FlowIATMax:   agg.MaxIATUs,
				FlowDuration: duration,
				PacketRate:   pktRate,
				ByteRate:     byteRate,
				PktLenMean:   lenMean,
				PktLenStd:    lenStd,
				PktLenMax:    agg.MaxPktLen,
				BytesIn:      agg.TotalBytes,
				BytesOut:     0,
				SYNCount:     agg.CntSYN,
				ACKCount:     agg.CntACK,
				RSTCount:     agg.CntRST,
				FINCount:     agg.CntFIN,
				SYNACKRatio:  synAckRatio,
				TTLMean:      float64(agg.SumTTL) / float64(agg.PktCount),
				WinSizeMean:  float64(agg.SumWinSize) / float64(agg.PktCount),
			}

			data, _ := json.Marshal(m)
			pipe.LPush(ctx, "ddos_metrics", data)
			count++

			if count >= 100 {
				pipe.Exec(ctx)
				pipe = rdb.Pipeline()
				count = 0
			}
		}
		if count > 0 {
			pipe.Exec(ctx)
		}
		if err := iter.Err(); err != nil {
			log.Printf("Error iterating flow metrics map: %v", err)
		}

		// Perform Eviction
		for _, k := range toDelete {
			if err := metricsMap.Delete(k); err != nil {
				// Ignore errors (key might be deleted by race, though PERCPU shouldn't race on delete)
			}
		}
	}
}

func redisPublisher(rdb *redis.Client, input <-chan AnalysisResult) {
	// Wait for Redis connection
	for {
		if err := rdb.Ping(context.Background()).Err(); err == nil {
			break
		}
		time.Sleep(5 * time.Second)
	}

	const batchSize = 100
	const batchTimeout = 100 * time.Millisecond

	buffer := make([]interface{}, 0, batchSize)
	ticker := time.NewTicker(batchTimeout)
	defer ticker.Stop()

	flush := func() {
		if len(buffer) == 0 {
			return
		}

		ctx := context.Background()
		pipe := rdb.Pipeline()
		pipe.LPush(ctx, "tls_fingerprints", buffer...)

		if _, err := pipe.Exec(ctx); err != nil {
			log.Printf("Redis pipeline error: %v", err)
		}
		buffer = buffer[:0]
	}

	for {
		select {
		case msg := <-input:
			body, _ := json.Marshal(msg)
			buffer = append(buffer, body)
			if len(buffer) >= batchSize {
				flush()
			}
		case <-ticker.C:
			flush()
		}
	}
}

func alertPublisher(rdb *redis.Client, input <-chan DDoSAlert) {
	for msg := range input {
		body, _ := json.Marshal(msg)
		if err := rdb.LPush(context.Background(), "ddos_alerts", body).Err(); err != nil {
			log.Printf("Failed to publish alert to Redis: %v", err)
		}
	}
}

func vectorDBWorker(vdb *VectorDB, input <-chan AnalysisResult) {
	if vdb == nil {
		// Drain channel if VDB failed to init
		for range input {
		}
		return
	}

	for msg := range input {
		vdb.SaveAndVerify(msg)
	}
}
