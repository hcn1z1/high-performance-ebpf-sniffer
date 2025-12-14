# Integration Guide

This guide explains how to integrate the JA4 Sniffer with other services and tools. The sniffer acts as a producer, publishing analyzed TLS fingerprint data to **Redis** for real-time consumption and **Qdrant** for long-term storage and vector similarity search.

## 1. Consuming Real-Time Data (Redis)

The sniffer publishes JSON events to a Redis list. External services (e.g., a SIEM forwarder, dashboard, or alerting bot) can consume these events by popping elements from the list.

### Connection Details
*   **Host:** `sniffer-redis` (internal Docker network) or `localhost` (if port mapped)
*   **Port:** `16379`
*   **List Key:** `tls_fingerprints`
*   **Method:** `LPOP` or `BLPOP` (blocking pop for efficiency)

### Data Format
Each event is a JSON object with the following structure:

```json
{
  "timestamp": "2023-10-27T10:00:00Z",
  "src_ip": "192.168.1.50",
  "dst_ip": "1.1.1.1",
  "src_port": 12345,
  "dst_port": 443,
  "ja4": "t13d1516h2_8daaf6152771_e82d46083166",
  "server_name": "example.com",
  "fingerprint_id": "unique-uuid-v4",
  "enrichment": [
    {
      "source": "ThreatFox",
      "malicious": true,
      "description": "Malware: CobaltStrike (botnet_cc)"
    }
  ],
  "similar_match": {
    "found": true,
    "score": 0.98,
    "description": "Known Malware Variant"
  }
}
```

### Python Example (Consumer)

```python
import redis
import json

# Connect to Redis
r = redis.Redis(host='localhost', port=6379, decode_responses=True)

print("Waiting for TLS events...")

while True:
    # Blocking pop: waits until an item is available
    _, data = r.blpop('tls_fingerprints')
    event = json.loads(data)

    print(f"[{event['timestamp']}] {event['src_ip']} -> {event['server_name']} ({event['ja4']})")

    if event.get('enrichment'):
        print(f"  [!] ALERT: {event['enrichment'][0]['description']}")
```

---

## 2. Querying Historical Data (Qdrant)

The sniffer stores vector representations of the JA4 fingerprints in Qdrant. You can query this database to find similar TLS clients (fuzzy matching) or exact matches.

### Connection Details
*   **Host:** `qdrant` (internal) or `localhost`
*   **HTTP Port:** `6333`
*   **gRPC Port:** `6334`
*   **Collection Name:** `tls_fingerprints`
*   **Vector Size:** 64 (Derived from SHA256 hashing of the JA4 string)

### Querying for Similarity
If you have a suspicious JA4 string (e.g., from a log file), you can search Qdrant for the "nearest neighbors" to identify what known tools or malware it resembles.

### Python Example (Search)

```python
from qdrant_client import QdrantClient
import hashlib

# Connect to Qdrant
client = QdrantClient("localhost", port=6333)

target_ja4 = "t13d1516h2_8daaf6152771_e82d46083166"

# Convert JA4 to vector (must match sniffer's logic)
def ja4_to_vector(ja4_str):
    # Deterministic hash mapping to 64 dimensions (simplified example)
    # Note: Refer to sniffer/vector_db.go for the exact implementation
    h = hashlib.sha256(ja4_str.encode()).digest()
    return [float(b) for b in h[:64]] # Pseudocode for dimensionality

vector = ja4_to_vector(target_ja4)

results = client.search(
    collection_name="tls_fingerprints",
    query_vector=vector,
    limit=5
)

for hit in results:
    print(f"Score: {hit.score}, Payload: {hit.payload}")
```

## 3. External API Integration

The service is designed to be enriched by external Threat Intelligence APIs. To enable this, ensure the following environment variables are set in `docker-compose.yml`:

*   `THREATFOX_API_KEY`: Abuse.ch ThreatFox
*   `GREYNOISE_API_KEY`: GreyNoise Enterprise
*   `VT_API_KEY`: VirusTotal
*   `JA4DB_API_KEY`: JA4 Database (FoxIO)

When these are set, the `sniffer` service will automatically query these APIs upon seeing a new fingerprint and include the results in the Redis JSON output.
