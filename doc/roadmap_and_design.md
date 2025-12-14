# Roadmap and Design Proposals

This document outlines proposed improvements to the sniffer service, focusing on security enhancements, AI integration, and mathematical analysis of network traffic.

## 1. DDoS Detection & Mitigation

### Current State
The current implementation passively monitors traffic via eBPF but does not actively block or analyze volumetric anomalies.

### Proposal: BPF-Based Rate Limiting
To detect and mitigate DDoS attacks (e.g., SYN floods) with minimal overhead, we can extend the BPF program.

*   **XDP (eXpress Data Path):** Move packet filtering from TC (Traffic Control) to XDP. XDP runs earlier in the driver path, allowing us to drop packets before the kernel allocates an `sk_buff`, providing extremely high performance.
*   **Counting Bloom Filter / Hash Map:** Use a BPF map (`BPF_MAP_TYPE_PERCPU_HASH`) to track packet counts per source IP or subnet.
*   **Thresholding:**
    *   If `SYN` packets from a single IP exceed `X` per second:
        *   Mark IP as "blocked" in a separate BPF map.
        *   XDP program immediately returns `XDP_DROP` for subsequent packets from that IP.
    *   Publish an alert event to userspace (Redis) indicating a DDoS attempt.

## 2. AI & Machine Learning Integration

### Current State
Vector embeddings are generated using a deterministic SHA256-based hash of the JA4 string. This allows for exact matching and simple "bit-difference" similarity but lacks semantic understanding of the TLS structure.

### Proposal: Learned Embeddings (Autoencoder)
Replace the deterministic hash with a trained Machine Learning model to generate vectors.

*   **Model:** Train a small Autoencoder or LSTM on a large dataset of TLS Client Hellos.
*   **Input:** Raw features of the Client Hello (Cipher Suites list, Extension types, ALPN, Supported Groups).
*   **Output:** A dense vector (embedding) that represents the "style" of the client.
*   **Benefit:**
    *   **Anomaly Detection:** A generic Python script impersonating a browser might have the same JA4 hash as the script, but a learned embedding could detect subtle ordering differences or unusual combinations that don't manifest in the standard JA4 string.
    *   **Clustering:** Better grouping of malware families that continually slightly modify their TLS parameters to evade exact signature matching.

### Proposal: Traffic Classifier
Implement a lightweight inference engine (e.g., ONNX Runtime or TensorFlow Lite) directly in the Go service.
*   **Features:** Packet Inter-arrival Times (IAT), Payload Sizes, Entropy, JA4.
*   **Goal:** classify flow as "Bot", "Browser", "Streaming", or "C2" (Command & Control) in real-time.

## 3. Mathematical Analysis & Statistics

### Entropy Analysis
Calculate the Shannon Entropy of the TLS record payload.
*   **Use Case:** High entropy often indicates encryption or compression. While TLS is encrypted, analyzing the entropy of the *unencrypted* handshake parts or the immediate post-handshake packets can reveal "steganography" or tunneling attempts inside TLS (e.g., domain fronting anomalies).

### Timing Analysis (Math)
*   **Sequence Prediction:** Use Markov Chains to model the sequence of packet sizes and directions.
*   **IAT (Inter-Arrival Time):**
    *   Compute the mean and standard deviation ($\sigma$) of packet arrival times for a flow.
    *   **Automated Beacon Detection:** C2 agents often beacon at regular intervals with added "jitter".
    *   **Formula:** If $Variance(IAT) \approx 0$ (or within a specific jitter threshold), flag as potential automated beacon.

## 4. Model Improvements

### Vector Generation Refinement
Currently, the vector dimension is fixed at 64.
*   **Dimensionality Reduction:** If we switch to a learned model, we can experiment with reducing dimensions (e.g., to 16 or 32) using PCA (Principal Component Analysis) to speed up Qdrant search performance without significant accuracy loss.
*   **Weighted Features:** Give more weight to "rare" Cipher Suites. In the vector generation logic, rare ciphers should influence the vector direction more than common ones (like `TLS_AES_128_GCM_SHA256`). This is analogous to TF-IDF in text processing.

### Dynamic Retraining
Create a feedback loop:
1.  Sniffer detects "Unknown" traffic.
2.  Analyst labels it in Qdrant.
3.  System periodically retrains the embedding model or updates the weighted feature map based on new labelled data.
