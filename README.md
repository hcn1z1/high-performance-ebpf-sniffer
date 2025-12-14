# High-performance EBPF Passive Sniffer (JA4 Fingerprinting)

This project is a high-performance passive network sniffer designed to capture TLS traffic on port 443, extract JA4 fingerprints, and publish the analysis to a Redis list. It leverages eBPF for efficient kernel-level packet capture and Go for high-concurrency userspace processing.

## Architecture

*   **eBPF (Kernel Probe):** Captures TCP packets on port 443. It filters for traffic and passes packet metadata and payload to userspace via a perf ring buffer.
*   **Go (Userspace Sniffer):** Consumes events from the perf ring buffer, parses packets using `gopacket`, extracts TLS handshake information to generate JA4 fingerprints.
*   **Vector Database (Qdrant):** Stores vector representations of JA4 fingerprints for similarity search and verification against known threats.
*   **Redis (Queue):** High-performance data store used to decouple the sniffer from downstream analysis.

## Services

*   **`sniffer`**: The main Go application.
*   **`sniffer-redis`**: Redis instance for message queuing.
*   **`qdrant`**: Vector database for fingerprint storage and verification.

## Prerequisites

*   **Linux Kernel:** Requires a kernel with eBPF support (roughly 4.18+, preferably newer 5.x).
*   **Docker & Docker Compose:** For containerized deployment.
*   **Privileges:** The sniffer container requires `privileged: true` and volume mounts for `/sys/fs/bpf` and `/sys/kernel/debug` to load BPF programs.

## External Intelligence Integration

This sniffer supports enrichment from the following services if API keys are provided in `docker-compose.yml` or the environment:

*   **ThreatFox:** Checks against known malware IOCs. (Env: `THREATFOX_API_KEY`)
*   **GreyNoise:** Checks if the JA4 is a known internet scanner or malicious IP. (Env: `GREYNOISE_API_KEY`)
*   **VirusTotal:** Checks behavioral network signatures for malware. (Env: `VT_API_KEY`)

### Offline Database Seeding

The system includes a `seeder` tool that automatically downloads known JA4 signatures (from FoxIO-LLC and the official JA4DB) and populates the Qdrant vector database. This runs as a container profile (`docker-compose --profile tools up seeder`).

## Directory Structure

```
.
├── docker-compose.yml    # Orchestration for Sniffer, Redis, and Qdrant
├── sniffer/              # Source code for the sniffer service
│   ├── Dockerfile        # Multi-stage build (Clang+Go builder -> Alpine runner)
│   ├── go.mod            # Go module definitions
│   ├── main.go           # Main application entry point (Fan-out to Redis/Qdrant)
│   ├── tls.go            # JA4 parsing logic
│   ├── vector_db.go      # Qdrant integration and JA4 vectorization
│   └── src/
│       └── bpf_program.c # eBPF C source code
└── tools/
    └── test_traffic.py   # Utility script to generate HTTPS traffic
```

## Features

*   **Passive Sniffing:** Uses `XDP` / `TC` (via eBPF) for non-intrusive monitoring.
*   **JA4 Fingerprinting:** Calculates `JA4_a_b_c` fingerprints for all TLS Client Hellos.
*   **Known Signature Verification:** Automatically downloads the official `ja4plus-mapping.csv` database during build and checks captured fingerprints against known applications/threats.
*   **Dual Output:** concurrently publishes analysis results to:
    *   **Redis** (`tls_fingerprints` list) for real-time processing.
    *   **Qdrant** (`tls_fingerprints` collection) for long-term storage and vector similarity search.

## Building and Running

### 1. Build and Start Services

Use Docker Compose to build the sniffer image and start the infrastructure:

```bash
docker-compose up --build -d
```

### 2. Verify Operation

Check the logs to ensure the sniffer has attached to the interface and connected to Qdrant:

```bash
docker-compose logs -f sniffer
```

You should see:
*   "Loaded X known JA4 signatures"
*   "Connected to Qdrant..."
*   "Sniffer started on eth0..."

### 3. Generate Traffic

You can use the provided tool to generate HTTPS traffic which should be captured if it flows through the monitored interface:

```bash
python3 tools/test_traffic.py
```

### 4. Consume Data

The sniffer publishes JSON data to the `tls_fingerprints` list in Redis. You can access it using `redis-cli`:

```bash
docker exec -it sniffer-redis redis-cli LPOP tls_fingerprints
```

## Development (Local Compilation)

To compile the project locally (requires `clang`, `llvm`, `libbpf-dev`, and `go`):

1.  **Compile BPF:**
    ```bash
    cd sniffer
    clang -O2 -g -target bpf -c src/bpf_program.c -o bpf_program.o
    ```

2.  **Compile Go:**
    ```bash
    go mod tidy
    go build -o sniffer_app .
    ```
