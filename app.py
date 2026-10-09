import streamlit as st
import pandas as pd
import plotly.express as px
from pathlib import Path

st.set_page_config(
    page_title="TRACE-X | Evidence Intelligence",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

BASE_DIR = Path(__file__).parent
DATA_DIR = BASE_DIR / "data"

st.markdown("""
<style>
:root { color-scheme: dark; }
.stApp {
  background:
    radial-gradient(circle at 10% 0%, rgba(0, 168, 255, .12), transparent 28%),
    radial-gradient(circle at 100% 10%, rgba(33, 94, 255, .10), transparent 25%),
    #07111f;
  color: #e5eefb;
}
[data-testid="stSidebar"] { background: #0a1728; border-right: 1px solid #17324d; }
.block-container { padding-top: 1.7rem; padding-bottom: 2.5rem; max-width: 1500px; }
h1, h2, h3 { color: #f3f8ff !important; }
.tx-hero {
  padding: 1.4rem 1.6rem; border: 1px solid #164e75; border-radius: 18px;
  background: linear-gradient(120deg, rgba(8, 35, 60, .96), rgba(10, 22, 43, .95));
  box-shadow: 0 0 32px rgba(0, 174, 255, .08);
  margin-bottom: 1.2rem;
}
.tx-eyebrow { color: #38bdf8; letter-spacing: .18em; font-size: .76rem; font-weight: 800; }
.tx-subtitle { color: #9db4cf; margin-top: .35rem; }
div[data-testid="stMetric"] {
  background: linear-gradient(160deg, #0d2035, #0b1829);
  border: 1px solid #183954; padding: 1rem 1.1rem; border-radius: 14px;
}
div[data-testid="stMetricLabel"] { color: #9db4cf; }
div[data-testid="stMetricValue"] { color: #e9f6ff; }
.stButton > button, .stDownloadButton > button {
  border: 1px solid #087cae; background: #0b2942; color: #e8f8ff;
  border-radius: 9px;
}
.stButton > button:hover, .stDownloadButton > button:hover {
  border-color: #38bdf8; background: #103a5c; color: white;
}
div[data-testid="stDataFrame"] { border: 1px solid #17324d; border-radius: 12px; overflow: hidden; }
hr { border-color: #18334d; }
.small-note { color: #8ea6c1; font-size: .86rem; }
.pill {
  display:inline-block; padding: .25rem .6rem; border-radius:999px;
  color:#7dd3fc; background:#0c2a42; border:1px solid #15577b;
  font-size:.75rem; font-weight:700;
}
</style>
""", unsafe_allow_html=True)

def load_csv(filename):
    path = DATA_DIR / filename
    if not path.exists():
        return pd.DataFrame()
    try:
        return pd.read_csv(path)
    except Exception as exc:
        st.error(f"Could not read {filename}: {exc}")
        return pd.DataFrame()

events = load_csv("normalized_events.csv")
timeline = load_csv("attack_timeline.csv")
email = load_csv("email_threat_analysis_results (3) (1).csv")
prioritized = load_csv("TRACEX_prioritized_events.csv")

for frame in (events, timeline, prioritized):
    if not frame.empty and "timestamp" in frame.columns:
        frame["timestamp"] = pd.to_datetime(frame["timestamp"], errors="coerce")

st.sidebar.markdown("## 🛡️ TRACE-X")
st.sidebar.caption("DIGITAL EVIDENCE INTELLIGENCE")
page = st.sidebar.radio(
    "NAVIGATION",
    ["Overview", "Evidence Search", "Investigation Timeline", "Events to Review", "Email Analysis"],
)
st.sidebar.markdown("---")
st.sidebar.markdown('<span class="pill">SYNTHETIC DATA DEMO</span>', unsafe_allow_html=True)
st.sidebar.caption("Review indicators are not confirmation of an attack.")

st.markdown("""
<div class="tx-hero">
  <div class="tx-eyebrow">TRACE-X / SECURITY OPERATIONS</div>
  <h1 style="margin:.45rem 0 0 0;">Evidence Intelligence Console</h1>
  <div class="tx-subtitle">A unified view of events, investigation leads, and review priorities.</div>
</div>
""", unsafe_allow_html=True)

if events.empty:
    st.error("The event data file is missing. Check that data/normalized_events.csv exists.")
    st.stop()

if page == "Overview":
    n_events = len(events)
    n_users = events["user"].replace("", pd.NA).dropna().nunique() if "user" in events else 0
    n_ips = events["ip"].replace("", pd.NA).dropna().nunique() if "ip" in events else 0
    n_types = events["event_type"].nunique() if "event_type" in events else 0
    phishing = None
    if not email.empty and "phishing_probability" in email:
        try:
            phishing = float(email.iloc[0]["phishing_probability"]) * 100
        except (ValueError, TypeError):
            phishing = None

    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Total Events", f"{n_events}")
    c2.metric("Known Users", f"{n_users}")
    c3.metric("Known IP Addresses", f"{n_ips}")
    c4.metric("Event Categories", f"{n_types}")
    st.markdown("### Event telemetry")
    left, right = st.columns([1.1, 1])
    with left:
        counts = events["event_type"].fillna("Unknown").value_counts().rename_axis("Event Type").reset_index(name="Events")
        fig = px.bar(counts, x="Event Type", y="Events", text="Events", color="Event Type",
                     color_discrete_sequence=["#38bdf8", "#2563eb", "#14b8a6", "#818cf8", "#f59e0b"])
        fig.update_layout(template="plotly_dark", paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
                          showlegend=False, margin=dict(l=10,r=10,t=20,b=10), font_color="#dbeafe")
        st.plotly_chart(fig, use_container_width=True)
    with right:
        st.markdown("#### Model advisory")
        if phishing is not None:
            st.metric("Email phishing probability", f"{phishing:.2f}%")
        if not email.empty:
            st.dataframe(email, use_container_width=True, hide_index=True)
        else:
            st.info("Email analysis output is not available.")
        st.caption("Model probabilities are advisory outputs and do not independently establish that an email is malicious.")
    st.markdown("### Recent evidence")
    recent = events.copy()
    if "timestamp" in recent:
        recent = recent.sort_values("timestamp", ascending=False)
    cols = [c for c in ["timestamp", "event_id", "event_type", "user", "ip", "description"] if c in recent]
    st.dataframe(recent[cols].head(8), use_container_width=True, hide_index=True)
    st.markdown('<div class="small-note">TRACE-X demo using the supplied project CSV files. Dataset is synthetic/small; risk scores in the source data are placeholders.</div>', unsafe_allow_html=True)

elif page == "Evidence Search":
    st.markdown("### Search and filter evidence")
    filtered = events.copy()
    if "timestamp" in filtered:
        filtered["timestamp"] = pd.to_datetime(filtered["timestamp"], errors="coerce")
    for col in ["event_type", "user", "ip"]:
        if col in filtered:
            filtered[col] = filtered[col].fillna("Unknown").replace("", "Unknown")
    a, b, c = st.columns(3)
    event_options = ["All"] + sorted(filtered["event_type"].unique().tolist()) if "event_type" in filtered else ["All"]
    user_options = ["All"] + sorted(filtered["user"].unique().tolist()) if "user" in filtered else ["All"]
    ip_options = ["All"] + sorted(filtered["ip"].unique().tolist()) if "ip" in filtered else ["All"]
    chosen_type = a.selectbox("Event type", event_options)
    chosen_user = b.selectbox("User", user_options)
    chosen_ip = c.selectbox("IP address", ip_options)
    search = st.text_input("Keyword search", placeholder="Search descriptions, domains, URLs, files…")
    if chosen_type != "All": filtered = filtered[filtered["event_type"] == chosen_type]
    if chosen_user != "All": filtered = filtered[filtered["user"] == chosen_user]
    if chosen_ip != "All": filtered = filtered[filtered["ip"] == chosen_ip]
    if search.strip():
        searchable = filtered.astype(str).apply(lambda col: col.str.contains(search, case=False, na=False))
        filtered = filtered[searchable.any(axis=1)]
    st.metric("Matching events", len(filtered))
    st.dataframe(filtered, use_container_width=True, hide_index=True)
    st.download_button("⬇ Download filtered evidence CSV", filtered.to_csv(index=False).encode("utf-8"), "TRACEX_filtered_evidence.csv", "text/csv")

elif page == "Investigation Timeline":
    st.markdown("### Chronological event timeline")
    source = timeline.copy() if not timeline.empty else events.copy()
    if "timestamp" in source:
        source["timestamp"] = pd.to_datetime(source["timestamp"], errors="coerce")
        source = source.sort_values("timestamp")
    if not source.empty and "timestamp" in source and "event_type" in source:
        source["timeline_label"] = source.get("event_id", pd.Series(["Event"]*len(source))).astype(str) + " · " + source["event_type"].astype(str)
        fig = px.scatter(source, x="timestamp", y="event_type", color="event_type", hover_data=[c for c in ["event_id","user","ip","domain","description"] if c in source],
                         color_discrete_sequence=["#38bdf8", "#818cf8", "#14b8a6", "#f59e0b", "#f472b6"])
        fig.update_traces(marker=dict(size=12, line=dict(width=1, color="#dbeafe")))
        fig.update_layout(template="plotly_dark", paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
                          margin=dict(l=10,r=10,t=25,b=10), font_color="#dbeafe", xaxis_title="Timestamp", yaxis_title="Event category")
        st.plotly_chart(fig, use_container_width=True)
    st.dataframe(source, use_container_width=True, hide_index=True)
    st.caption("Chronological proximity can help guide review but does not by itself prove causation or an attack.")

elif page == "Events to Review":
    st.markdown("### Events flagged for manual review")
    if prioritized.empty:
        st.warning("Prioritized events file is missing.")
    else:
        if "review_priority" not in prioritized:
            prioritized["review_priority"] = "REVIEW"
        a,b,c = st.columns(3)
        high = int((prioritized["review_priority"] == "HIGH").sum())
        med = int((prioritized["review_priority"] == "MEDIUM").sum())
        review = int((prioritized["review_priority"] == "REVIEW").sum())
        a.metric("HIGH", high)
        b.metric("MEDIUM", med)
        c.metric("REVIEW", review)
        choice = st.multiselect("Show priorities", ["HIGH","MEDIUM","REVIEW"], default=["HIGH","MEDIUM","REVIEW"])
        shown = prioritized[prioritized["review_priority"].isin(choice)].copy()
        if "timestamp" in shown:
            shown = shown.sort_values("timestamp")
        st.dataframe(shown, use_container_width=True, hide_index=True)
        counts = shown["review_priority"].value_counts().reindex(["HIGH","MEDIUM","REVIEW"], fill_value=0).rename_axis("Priority").reset_index(name="Events")
        fig = px.bar(counts, x="Priority", y="Events", text="Events", color="Priority",
                     color_discrete_map={"HIGH":"#fb7185","MEDIUM":"#fbbf24","REVIEW":"#60a5fa"})
        fig.update_layout(template="plotly_dark", paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
                          showlegend=False, margin=dict(l=10,r=10,t=20,b=10), font_color="#dbeafe")
        st.plotly_chart(fig, use_container_width=True)
        st.download_button("⬇ Download prioritized report", shown.to_csv(index=False).encode("utf-8"), "TRACEX_prioritized_events.csv", "text/csv")
        st.warning("Priority labels are simple rule-based triage suggestions. They are not validated threat scores or proof of malicious activity.")

elif page == "Email Analysis":
    st.markdown("### Email threat analysis")
    if email.empty:
        st.info("Email analysis file is not available.")
    else:
        row = email.iloc[0]
        label = str(row.get("predicted_label", "Unknown")).upper()
        st.metric("Model predicted label", label)
        if "benign_probability" in email and "phishing_probability" in email:
            try:
                benign = float(row["benign_probability"]) * 100
                phish = float(row["phishing_probability"]) * 100
                a,b = st.columns(2)
                a.metric("Benign probability", f"{benign:.2f}%")
                b.metric("Phishing probability", f"{phish:.2f}%")
                probs = pd.DataFrame({"Class":["Benign","Phishing"],"Probability (%)":[benign,phish]})
                fig = px.bar(probs, x="Class", y="Probability (%)", text=probs["Probability (%)"].map(lambda x:f"{x:.2f}%"),
                             color="Class", color_discrete_map={"Benign":"#38bdf8","Phishing":"#fb7185"})
                fig.update_layout(template="plotly_dark", paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
                                  showlegend=False, margin=dict(l=10,r=10,t=20,b=10), font_color="#dbeafe")
                st.plotly_chart(fig, use_container_width=True)
            except (ValueError, TypeError):
                pass
        st.dataframe(email, use_container_width=True, hide_index=True)
        st.warning("This is a model output for investigation support, not a definitive determination that the email is phishing.")
