import streamlit as st
import redis
import json
import pandas as pd
import time
import os

# --- Configuration ---
# Use the Docker service name if running in the same network
REDIS_HOST = os.getenv("REDIS_HOST", "localhost") 
REDIS_PORT = int(os.getenv("REDIS_PORT", 6379))
DDOS_KEY = "ddos_metrics"
JA4_KEY = "tls_fingerprints"

st.set_page_config(page_title="Network Sentinel", layout="wide")
st.title("🛡️ Network Sentinel Dashboard")

# --- Connect to Redis ---
@st.cache_resource
def get_redis():
    try:
        return redis.Redis(host=REDIS_HOST, port=REDIS_PORT, db=0, decode_responses=True)
    except:
        return None

r = get_redis()

# --- Initialize Data Buffers in Session State ---
if 'ddos_buffer' not in st.session_state:
    st.session_state.ddos_buffer = []
if 'ja4_buffer' not in st.session_state:
    st.session_state.ja4_buffer = []

# --- Layout: Tabs & Placeholders ---
# We create the tabs and placeholders ONCE outside the loop.
tab_ddos, tab_ja4 = st.tabs(["🔥 DDoS Monitor", "🔍 JA4 Fingerprints"])

with tab_ddos:
    ddos_placeholder = st.empty()

with tab_ja4:
    ja4_placeholder = st.empty()

def main():
    if r is None:
        st.error(f"Could not connect to Redis at {REDIS_HOST}:{REDIS_PORT}")
        return

    st.toast("Monitoring active... listening for packets.", icon="📡")

    while True:
        # Non-blocking pops
        raw_ddos = r.lpop(DDOS_KEY)
        raw_ja4 = r.lpop(JA4_KEY)

        updated_ddos = False
        updated_ja4 = False

        # --- Process DDoS Data ---
        if raw_ddos:
            try:
                data = json.loads(raw_ddos)
                data['time'] = pd.Timestamp.now()
                st.session_state.ddos_buffer.append(data)
                if len(st.session_state.ddos_buffer) > 100:
                    st.session_state.ddos_buffer.pop(0)
                updated_ddos = True
            except json.JSONDecodeError:
                pass

        # --- Process JA4 Data ---
        if raw_ja4:
            try:
                data = json.loads(raw_ja4)
                data['time'] = pd.Timestamp.now()
                st.session_state.ja4_buffer.append(data)
                if len(st.session_state.ja4_buffer) > 100:
                    st.session_state.ja4_buffer.pop(0)
                updated_ja4 = True
            except json.JSONDecodeError:
                pass

        # --- Render DDoS Tab ---
        if updated_ddos or (len(st.session_state.ddos_buffer) > 0 and not raw_ddos):
             # We render even if no new data came in this exact millisecond,
             # but strictly speaking we only need to re-render on change.
             # However, for smooth "live" feel, re-rendering the latest state is okay.
             # To save CPU, we could only render if 'updated_ddos' is True OR if it's the first run.
             # For simplicity in this loop, we render on every tick (or if we want to optimize, only on update).
             # Let's render on update or if buffer exists (to show initial state).

            with ddos_placeholder.container():
                if not st.session_state.ddos_buffer:
                    st.info("Waiting for DDoS metrics...")
                else:
                    df = pd.DataFrame(st.session_state.ddos_buffer).set_index('time')
                    latest = st.session_state.ddos_buffer[-1]
                    
                    # 1. Metrics
                    kpi1, kpi2, kpi3, kpi4 = st.columns(4)
                    kpi1.metric("Source IP", latest.get("src_ip", "N/A"))
                    kpi2.metric("Packet Rate", f"{latest.get('packet_rate', 0):.0f} pps")
                    kpi3.metric("Byte Rate", f"{latest.get('byte_rate', 0)/1024:.1f} KB/s")
                    kpi4.metric("Syn/Ack Ratio", f"{latest.get('syn_ack_ratio', 0):.2f}")

                    st.divider()

                    # 2. Charts
                    c1, c2 = st.columns(2)
                    c1.subheader("Traffic Velocity")
                    c1.line_chart(df[['packet_rate']])

                    c2.subheader("SYN/ACK Ratio")
                    c2.line_chart(df[['syn_ack_ratio']])

                    # 3. Logs
                    with st.expander("Raw Packet Logs", expanded=True):
                        cols = ['src_ip', 'packet_rate', 'syn_count', 'ack_count', 'flow_iat_mean']
                        valid_cols = [c for c in cols if c in df.columns]
                        st.dataframe(df[valid_cols].sort_index(ascending=False).head(5), use_container_width=True)

        # --- Render JA4 Tab ---
        if updated_ja4 or (len(st.session_state.ja4_buffer) > 0 and not raw_ja4):
            with ja4_placeholder.container():
                if not st.session_state.ja4_buffer:
                    st.info("Waiting for TLS Fingerprints...")
                else:
                    df_ja4 = pd.DataFrame(st.session_state.ja4_buffer).set_index('time')

                    # 1. Top Level Stats
                    latest_ja4 = st.session_state.ja4_buffer[-1]
                    m1, m2, m3 = st.columns(3)
                    m1.metric("Latest Source", latest_ja4.get("src_ip", "N/A"))
                    m2.metric("Latest JA4", latest_ja4.get("ja4", "N/A")[:10]+"...")
                    score = latest_ja4.get("similarity_score", 0.0)
                    m3.metric("Similarity Score", f"{score:.4f}")

                    st.divider()

                    # 2. Main Data Table
                    st.subheader("TLS Fingerprint Stream")

                    # Select and reorder columns
                    display_cols = ['src_ip', 'dst_ip', 'dst_port', 'ja4', 'closest_match', 'similarity_score', 'match_desc']
                    # Filter to available columns
                    final_cols = [c for c in display_cols if c in df_ja4.columns]

                    # Sort by time descending (newest first)
                    st.dataframe(
                        df_ja4[final_cols].sort_index(ascending=False).head(20),
                        use_container_width=True,
                        column_config={
                            "similarity_score": st.column_config.ProgressColumn(
                                "Similarity",
                                help="Similarity score to known threats",
                                min_value=0,
                                max_value=1,
                                format="%.4f",
                            ),
                            "ja4": st.column_config.TextColumn("JA4 Fingerprint", width="medium"),
                        }
                    )

        time.sleep(0.1)

if __name__ == "__main__":
    main()
