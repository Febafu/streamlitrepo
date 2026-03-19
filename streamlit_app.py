"""
streamlit_app.py — ThreatScope Observatory
===========================================
Phishing URL Analysis Dashboard — fully interactive with Plotly.
All Plotly colors use rgba() — 8-digit hex is NOT supported by Plotly.

Run:  streamlit run streamlit_app.py
Deps: pip install requests pandas plotly streamlit
"""

import os, io, zipfile, time, random
from collections import Counter
from datetime import datetime, timedelta, timezone
from urllib.parse import urlparse

import requests
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st

# ══════════════════════════════════════════════════════════════
#  COLOUR SYSTEM
#  All Plotly colors MUST be plain 6-digit hex or rgba().
#  Never pass 8-digit hex (#rrggbbaa) to Plotly — it raises ValueError.
# ══════════════════════════════════════════════════════════════

# Solid colours (safe everywhere)
C_BG    = "#04070f"
C_PAPER = "#080f1a"
C_CARD  = "#0a1628"
C_BORD  = "#112244"
C_ORG   = "#ff4f2b"
C_ICE   = "#7dd3fc"
C_GOLD  = "#fbbf24"
C_TEAL  = "#2dd4bf"
C_PURP  = "#c084fc"
C_ROSE  = "#fb7185"
C_LIME  = "#a3e635"
C_TEXT  = "#e0f0ff"
C_MUTED = "#2a4060"

def rgba(hex6: str, a: float) -> str:
    """Convert a plain 6-digit hex colour + alpha (0-1) to 'rgba(r,g,b,a)'.
    Use this wherever Plotly needs a semi-transparent colour."""
    h = hex6.lstrip("#")
    r, g, b = int(h[0:2], 16), int(h[2:4], 16), int(h[4:6], 16)
    return f"rgba({r},{g},{b},{a})"

# ── Constants ─────────────────────────────────────────────────
OUTPUT_DIR    = "output"
URLHAUS_CSV   = "https://urlhaus.abuse.ch/downloads/csv_recent/"
URLHAUS_JSON  = "https://urlhaus-api.abuse.ch/v1/urls/recent/"
THREATFOX_API = "https://threatfox-api.abuse.ch/api/v1/"
HDRS          = {"User-Agent": "AcademyPhishingProject/1.0"}
REQUIRED      = ["source","url","status","date_added","threat","tags","host","country_code"]

# ── Plotly base layout (no 8-digit hex anywhere) ──────────────
def plotly_base(**extra):
    base = dict(
        paper_bgcolor=C_PAPER,
        plot_bgcolor=C_CARD,
        font=dict(family="IBM Plex Mono, monospace", color=C_TEXT, size=11),
        margin=dict(l=10, r=10, t=44, b=10),
        xaxis=dict(gridcolor=C_BORD, zerolinecolor=C_BORD, linecolor=C_BORD),
        yaxis=dict(gridcolor=C_BORD, zerolinecolor=C_BORD, linecolor=C_BORD),
    )
    base.update(extra)
    return base

# ══════════════════════════════════════════════════════════════
#  PAGE CONFIG  (first Streamlit call)
# ══════════════════════════════════════════════════════════════
st.set_page_config(
    page_title="ThreatScope | Phishing Observatory",
    page_icon="🔭",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ══════════════════════════════════════════════════════════════
#  CSS  — animated background, fonts, component overrides
# ══════════════════════════════════════════════════════════════
st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=Orbitron:wght@400;700;900&family=IBM+Plex+Mono:wght@300;400;600&display=swap');

html, body, .stApp {
    background: #04070f !important;
    color: #e0f0ff;
    font-family: 'IBM Plex Mono', monospace;
}
.block-container { padding: 1rem 2rem 4rem; max-width: 1600px; }

/* ── Animated particle-grid background ── */
.stApp::before {
    content: "";
    position: fixed;
    inset: 0;
    z-index: 0;
    pointer-events: none;
    background:
        radial-gradient(ellipse 80% 60% at 20% 10%, rgba(125,211,252,0.07) 0%, transparent 60%),
        radial-gradient(ellipse 60% 80% at 80% 90%, rgba(255,79,43,0.06) 0%, transparent 60%),
        radial-gradient(ellipse 50% 50% at 50% 50%, rgba(192,132,252,0.04) 0%, transparent 70%),
        linear-gradient(180deg, #04070f 0%, #06101a 50%, #04070f 100%);
    animation: bgPulse 12s ease-in-out infinite alternate;
}
@keyframes bgPulse {
    0%   { opacity: 0.7; }
    100% { opacity: 1.0; }
}

/* Horizontal scan sweep */
.stApp::after {
    content: "";
    position: fixed;
    left: 0; right: 0;
    height: 1px;
    background: linear-gradient(90deg,
        transparent 0%,
        rgba(125,211,252,0.0) 20%,
        rgba(125,211,252,0.5) 50%,
        rgba(255,79,43,0.4) 70%,
        transparent 100%);
    animation: scanline 8s linear infinite;
    z-index: 1;
    pointer-events: none;
}
@keyframes scanline {
    0%   { top: -2px; opacity: 0; }
    5%   { opacity: 1; }
    95%  { opacity: 1; }
    100% { top: 100vh; opacity: 0; }
}

/* Dot grid overlay */
.grid-bg {
    position: fixed;
    inset: 0;
    z-index: 0;
    pointer-events: none;
    background-image: radial-gradient(circle, rgba(125,211,252,0.08) 1px, transparent 1px);
    background-size: 40px 40px;
    animation: gridDrift 20s linear infinite;
}
@keyframes gridDrift {
    0%   { background-position: 0 0; }
    100% { background-position: 40px 40px; }
}

/* ── Title ── */
.obs-title {
    font-family: 'Orbitron', sans-serif;
    font-size: 2.6rem;
    font-weight: 900;
    background: linear-gradient(135deg, #7dd3fc 0%, #ff4f2b 50%, #fbbf24 100%);
    -webkit-background-clip: text;
    -webkit-text-fill-color: transparent;
    background-clip: text;
    letter-spacing: 4px;
    text-transform: uppercase;
    margin: 0;
    animation: titleGlow 4s ease-in-out infinite alternate;
}
@keyframes titleGlow {
    0%   { filter: drop-shadow(0 0 10px rgba(125,211,252,0.4)); }
    50%  { filter: drop-shadow(0 0 20px rgba(255,79,43,0.4)); }
    100% { filter: drop-shadow(0 0 10px rgba(251,191,36,0.4)); }
}
.obs-sub {
    font-family: 'IBM Plex Mono', monospace;
    font-size: 0.68rem;
    letter-spacing: 4px;
    color: #2a5070;
    text-transform: uppercase;
    margin-top: 4px;
}

/* ── Section headers ── */
.sec-head {
    font-family: 'Orbitron', sans-serif;
    font-size: 0.85rem;
    font-weight: 700;
    letter-spacing: 3px;
    text-transform: uppercase;
    color: #7dd3fc;
    padding: 14px 0 8px;
    border-bottom: 1px solid #112244;
    margin-bottom: 14px;
    display: flex;
    align-items: center;
    gap: 10px;
}
.sec-head::before {
    content: "";
    display: inline-block;
    width: 3px; height: 18px;
    background: linear-gradient(#ff4f2b, #7dd3fc);
    border-radius: 2px;
    flex-shrink: 0;
}

/* ── Metric cards ── */
div[data-testid="metric-container"] {
    background: linear-gradient(135deg, #0a1628 0%, #0d1f3c 100%);
    border: 1px solid #1a2e4a;
    border-radius: 10px;
    padding: 16px 18px 12px;
    position: relative;
    overflow: hidden;
    transition: all 0.3s ease;
}
div[data-testid="metric-container"]:hover {
    border-color: rgba(125,211,252,0.35);
    box-shadow: 0 0 24px rgba(125,211,252,0.08);
    transform: translateY(-2px);
}
div[data-testid="metric-container"]::after {
    content: "";
    position: absolute;
    bottom: 0; left: 0; right: 0; height: 2px;
    background: linear-gradient(90deg, #ff4f2b, #7dd3fc, #c084fc);
    opacity: 0.6;
}
[data-testid="stMetricLabel"] {
    color: #2a5070 !important;
    font-family: 'IBM Plex Mono', monospace !important;
    font-size: 0.65rem !important;
    text-transform: uppercase;
    letter-spacing: 2px;
}
[data-testid="stMetricValue"] {
    color: #7dd3fc !important;
    font-family: 'Orbitron', monospace !important;
    font-size: 1.7rem !important;
    font-weight: 700 !important;
}

/* ── Sidebar ── */
section[data-testid="stSidebar"] {
    background: #060d1a !important;
    border-right: 1px solid #112244;
}

/* ── Buttons ── */
.stButton > button {
    background: linear-gradient(135deg, #0a1628, #0d2040) !important;
    border: 1px solid rgba(125,211,252,0.35) !important;
    color: #7dd3fc !important;
    font-family: 'IBM Plex Mono', monospace !important;
    letter-spacing: 2px; text-transform: uppercase;
    font-size: 0.72rem; border-radius: 6px; padding: 10px 22px;
    transition: all 0.25s ease;
}
.stButton > button:hover {
    border-color: #7dd3fc !important;
    box-shadow: 0 0 18px rgba(125,211,252,0.2);
    transform: translateY(-1px);
}

/* ── Download button ── */
.stDownloadButton > button {
    background: linear-gradient(135deg, #1a0800, #2a1000) !important;
    border: 1px solid rgba(255,79,43,0.5) !important;
    color: #ff4f2b !important;
    font-family: 'IBM Plex Mono', monospace !important;
}
.stDownloadButton > button:hover {
    box-shadow: 0 0 18px rgba(255,79,43,0.2);
}

/* ── Inputs ── */
.stTextInput > div > div > input {
    background: #0a1628 !important;
    border: 1px solid #112244 !important;
    color: #e0f0ff !important;
    font-family: 'IBM Plex Mono', monospace !important;
    border-radius: 6px;
}
.stTextInput > div > div > input:focus {
    border-color: rgba(125,211,252,0.6) !important;
    box-shadow: 0 0 12px rgba(125,211,252,0.1) !important;
}

/* ── Sliders / selects ── */
[data-testid="stMultiSelect"] label,
[data-testid="stSelectbox"] label,
[data-testid="stSlider"] label {
    color: #2a5070 !important;
    font-family: 'IBM Plex Mono', monospace;
    font-size: 0.65rem; letter-spacing: 2px; text-transform: uppercase;
}

/* ── Divider ── */
hr { border-color: #112244 !important; opacity: 0.5; }

/* ── Expander ── */
details {
    background: #0a1628;
    border: 1px solid #112244 !important;
    border-radius: 8px; padding: 4px 12px;
}
details summary {
    font-family: 'IBM Plex Mono', monospace;
    font-size: 0.78rem; color: #7dd3fc !important;
    letter-spacing: 2px; text-transform: uppercase;
}

/* ── Tabs ── */
.stTabs [data-baseweb="tab-list"] {
    background: #060d1a;
    border-bottom: 1px solid #112244;
    gap: 2px;
}
.stTabs [data-baseweb="tab"] {
    background: transparent;
    color: #2a5070;
    font-family: 'IBM Plex Mono', monospace;
    font-size: 0.72rem; letter-spacing: 1px; text-transform: uppercase;
    border-radius: 6px 6px 0 0;
    padding: 10px 18px;
    transition: all 0.2s;
}
.stTabs [aria-selected="true"] {
    background: #0a1628 !important;
    color: #7dd3fc !important;
    border-bottom: 2px solid #7dd3fc !important;
}
.stTabs [data-baseweb="tab"]:hover { color: #e0f0ff !important; }

/* ── Scrollbar ── */
::-webkit-scrollbar { width: 5px; height: 5px; }
::-webkit-scrollbar-track { background: #04070f; }
::-webkit-scrollbar-thumb { background: #112244; border-radius: 3px; }
::-webkit-scrollbar-thumb:hover { background: #1a3060; }

/* ── Caption ── */
.stCaption { color: #1a3050 !important; font-family: 'IBM Plex Mono', monospace; font-size: 0.63rem; }

/* ── Pulse orb ── */
@keyframes orbPulse {
    0%, 100% { box-shadow: 0 0 0 0 rgba(45,212,191,0.5); }
    50%       { box-shadow: 0 0 0 8px rgba(45,212,191,0); }
}
.orb {
    display: inline-block; width: 8px; height: 8px; border-radius: 50%;
    background: #2dd4bf; margin-right: 8px; vertical-align: middle;
    animation: orbPulse 2s ease infinite;
}

/* ── Ticker ── */
@keyframes tickerScroll {
    0%   { transform: translateX(100vw); }
    100% { transform: translateX(-100%); }
}
.ticker-outer {
    overflow: hidden;
    background: #060d1a;
    border: 1px solid #112244;
    border-radius: 6px;
    padding: 7px 0;
    margin: 10px 0 0;
    position: relative;
}
.ticker-outer::before {
    content: "LIVE";
    position: absolute; left: 12px; top: 50%; transform: translateY(-50%);
    font-family: 'Orbitron', sans-serif;
    font-size: 0.6rem; color: #ff4f2b; letter-spacing: 2px;
    z-index: 2;
    background: #060d1a;
    padding-right: 8px;
}
.ticker-track {
    white-space: nowrap;
    display: inline-block;
    padding-left: 80px;
    animation: tickerScroll 30s linear infinite;
    font-family: 'IBM Plex Mono', monospace;
    font-size: 0.7rem; color: #2a5070; letter-spacing: 1px;
}
.tick { display: inline-block; margin: 0 36px; }
.tick b { color: #7dd3fc; }

/* ── Inspector card ── */
.icard {
    background: linear-gradient(135deg, #0a1628, #0d2040);
    border: 1px solid rgba(125,211,252,0.2);
    border-radius: 10px; padding: 20px 24px; margin: 8px 0;
}
.irow {
    display: flex; justify-content: space-between;
    padding: 7px 0; border-bottom: 1px solid #0d2040;
    font-family: 'IBM Plex Mono', monospace; font-size: 0.78rem;
}
.irow:last-child { border-bottom: none; }
.ikey  { color: #2a5070; letter-spacing: 1px; }
.ival  { color: #e0f0ff; font-weight: 600; max-width: 65%; word-break: break-all; text-align: right; }

/* ── Badges ── */
.b-crit { background: rgba(255,79,43,0.12); color: #ff4f2b; border: 1px solid rgba(255,79,43,0.35); border-radius: 5px; padding: 3px 10px; font-size: 0.7rem; font-family: 'IBM Plex Mono',monospace; display:inline-block; }
.b-high { background: rgba(251,191,36,0.12); color: #fbbf24; border: 1px solid rgba(251,191,36,0.35); border-radius: 5px; padding: 3px 10px; font-size: 0.7rem; font-family: 'IBM Plex Mono',monospace; display:inline-block; }
.b-med  { background: rgba(192,132,252,0.12); color: #c084fc; border: 1px solid rgba(192,132,252,0.35); border-radius: 5px; padding: 3px 10px; font-size: 0.7rem; font-family: 'IBM Plex Mono',monospace; display:inline-block; }
.b-low  { background: rgba(45,212,191,0.12);  color: #2dd4bf; border: 1px solid rgba(45,212,191,0.35);  border-radius: 5px; padding: 3px 10px; font-size: 0.7rem; font-family: 'IBM Plex Mono',monospace; display:inline-block; }
</style>
""", unsafe_allow_html=True)

# Animated dot grid
st.markdown("<div class='grid-bg'></div>", unsafe_allow_html=True)


# ══════════════════════════════════════════════════════════════
#  HELPERS
# ══════════════════════════════════════════════════════════════

def extract_tld(url: str) -> str:
    try:
        host = urlparse(url).hostname or ""
        parts = host.split(".")
        return "." + parts[-1] if len(parts) > 1 else "unknown"
    except Exception:
        return "unknown"

def enrich(df: pd.DataFrame) -> pd.DataFrame:
    if df.empty:
        return df
    # Safe access — if API schema changes and date_added is missing, default to NaT
    if "date_added" in df.columns:
        df["date_added"] = pd.to_datetime(df["date_added"], errors="coerce", utc=True)
    else:
        df["date_added"] = pd.NaT
    df["tld"]        = df["url"].apply(extract_tld)
    df["scheme"]     = df["url"].apply(lambda u: urlparse(u).scheme.lower() if pd.notna(u) and u else "unknown")
    df["path_depth"] = df["url"].apply(
        lambda u: len([p for p in urlparse(u).path.split("/") if p]) if pd.notna(u) and u else 0)
    return df

def empty_df():
    return pd.DataFrame(columns=REQUIRED)

def score_risk(url: str) -> tuple:
    risk, flags = 0, []
    try:
        parsed = urlparse(url)
        host   = parsed.hostname or ""
        path   = parsed.path
        if parsed.scheme == "http":
            risk += 15; flags.append("Insecure HTTP")
        tld = "." + host.split(".")[-1] if "." in host else ""
        if tld in [".xyz",".top",".tk",".pw",".cc",".site",".online",".info"]:
            risk += 20; flags.append(f"High-risk TLD ({tld})")
        if any(w in host+path for w in ["login","secure","account","verify","bank","paypal","amazon","microsoft","apple","confirm","update"]):
            risk += 25; flags.append("Credential/brand keyword")
        if len([p for p in path.split("/") if p]) >= 4:
            risk += 15; flags.append("Deep path structure")
        if any(path.endswith(e) for e in [".exe",".bat",".zip",".jar",".msi",".dll",".ps1"]):
            risk += 30; flags.append("Executable file extension")
        if path.endswith(".php"):
            risk += 10; flags.append("PHP endpoint")
        if len(host) > 40:
            risk += 10; flags.append("Long hostname")
        parts = host.replace("-","").split(".")
        if any(len(p) > 20 for p in parts):
            risk += 10; flags.append("Random-looking subdomain")
    except Exception:
        pass
    return min(risk, 100), flags


# ══════════════════════════════════════════════════════════════
#  DATA — synthetic fallback built-in
# ══════════════════════════════════════════════════════════════

def make_synthetic(n: int = 1500) -> pd.DataFrame:
    random.seed(42)
    now    = datetime.now(timezone.utc)
    tlds   = [".com"]*30+[".net"]*10+[".xyz"]*12+[".top"]*10+[".ru"]*8+[".tk"]*7+[".cn"]*6+[".de"]*5+[".info"]*5+[".org"]*4+[".io"]*4+[".cc"]*3+[".pw"]*3+[".site"]*3
    words  = ["login","secure","account","update","verify","bank","paypal","amazon","microsoft","apple","google","support","confirm","access","portal","download","invoice","payment","billing","alert"]
    paths  = ["/wp-content/uploads/","/images/","/js/","/admin/","/include/","/files/","/data/","/php/","/temp/","/assets/"]
    exts   = [".php",".exe",".zip",".doc",".xls","",".bat"]
    stats  = ["online"]*35+["offline"]*55+["unknown"]*10
    thrts  = ["malware_download"]*30+["phishing"]*35+["botnet_cc"]*15+["exploit_kit"]*10+["spam"]*10
    tags_p = ["Emotet","AgentTesla","Formbook","AsyncRAT","RedLine","QakBot","Cobalt Strike","IcedID","PlugX","njRAT","LokiBot","Remcos","BazaLoader","Ursnif","Dridex"]
    ctrys  = ["US"]*25+["RU"]*15+["CN"]*10+["DE"]*8+["NL"]*7+["FR"]*6+["GB"]*5+["UA"]*5+["BR"]*4+["IN"]*3+["HK"]*3+["SG"]*3+["JP"]*2+["KR"]*2
    schms  = ["http"]*72+["https"]*28
    records = []
    for i in range(n):
        tld   = random.choice(tlds)
        word  = random.choice(words)
        rs    = "".join(random.choices("abcdefghijklmnopqrstuvwxyz0123456789", k=6))
        host  = f"{word}-{rs}{tld}"
        schm  = random.choice(schms)
        path  = random.choice(paths)+random.choice(words)+random.choice(exts)
        url   = f"{schm}://{host}{path}"
        base  = now - timedelta(days=random.expovariate(0.25))
        if random.random() < 0.22:
            base = now - timedelta(days=random.uniform(4.5, 5.5))
        tc    = random.choices([0,1,2], weights=[30,50,20])[0]
        tags  = "|".join(random.sample(tags_p, min(tc, len(tags_p))))
        src   = "urlhaus" if i < int(n*0.8) else "threatfox"
        records.append({
            "source":src, "url":url,
            "status":random.choice(stats),
            "date_added":base.strftime("%Y-%m-%d %H:%M:%S"),
            "threat":random.choice(thrts), "tags":tags,
            "host":host, "country_code":random.choice(ctrys),
        })
    df = pd.DataFrame(records)
    for col in REQUIRED:
        if col not in df.columns: df[col] = ""
    return enrich(df)

@st.cache_data(ttl=3600, show_spinner=False)
def load_data():
    # Try combined.csv from phishing_analysis.py first
    path = f"{OUTPUT_DIR}/combined.csv"
    if os.path.exists(path):
        try:
            df = pd.read_csv(path)
            for col in REQUIRED:
                if col not in df.columns: df[col] = ""
            return enrich(df), "CACHED CSV"
        except Exception:
            pass
    # Live fetch
    return fetch_live()

def fetch_live():
    records, errs = [], []

    # URLhaus — try CSV first (no auth needed, plain download)
    try:
        r = requests.get(URLHAUS_CSV, timeout=30, headers=HDRS)
        r.raise_for_status()
        raw_bytes = r.content
        try:
            with zipfile.ZipFile(io.BytesIO(raw_bytes)) as z:
                cname = [n for n in z.namelist() if n.endswith(".csv")][0]
                raw   = z.open(cname).read().decode("utf-8", errors="replace")
        except zipfile.BadZipFile:
            raw = raw_bytes.decode("utf-8", errors="replace")
        lines = [l for l in raw.splitlines() if l and not l.startswith("#")]
        dfcsv = pd.read_csv(io.StringIO("\n".join(lines)),
            names=["id","date_added","url","url_status","last_online","threat","tags","urlhaus_link","reporter"],
            on_bad_lines="skip")
        for _, row in dfcsv.iterrows():
            records.append({
                "source":"urlhaus", "url":str(row.get("url","")),
                "status":str(row.get("url_status", row.get("status","unknown"))),
                "date_added":str(row.get("date_added","")),
                "threat":str(row.get("threat","")), "tags":str(row.get("tags","")),
                "host":urlparse(str(row.get("url",""))).hostname or "", "country_code":"",
            })
    except Exception as e1:
        errs.append(f"URLhaus CSV: {e1}")
        try:
            r = requests.post(URLHAUS_JSON, data={"limit":1000}, timeout=30, headers=HDRS)
            r.raise_for_status()
            for e in r.json().get("urls",[]):
                tags = "|".join(t.get("id","") for t in (e.get("tags") or []))
                records.append({"source":"urlhaus","url":e.get("url",""),
                    "status":e.get("url_status","unknown"),"date_added":e.get("date_added",""),
                    "threat":e.get("threat",""),"tags":tags,
                    "host":e.get("host",""),"country_code":e.get("country_code","")})
        except Exception as e2:
            errs.append(f"URLhaus JSON: {e2}")

    time.sleep(1.2)

    # ThreatFox — 401/403 handled gracefully; API key slot provided
    # To use a key: obtain one free at https://threatfox.abuse.ch/api/
    # then set THREATFOX_API_KEY = "your-key-here" near the top of this file.
    THREATFOX_API_KEY = ""   # <-- INSERT KEY HERE if you have one
    tf_hdrs = dict(HDRS)
    if THREATFOX_API_KEY:
        tf_hdrs["Auth-Key"] = THREATFOX_API_KEY
    try:
        r = requests.post(THREATFOX_API, json={"query":"get_iocs","days":7},
                          timeout=30, headers=tf_hdrs)
        if r.status_code in (401, 403):
            # 401 is normal without a key on restricted networks — not a crash
            errs.append(f"ThreatFox: {r.status_code} (no API key configured — set THREATFOX_API_KEY)")
        else:
            r.raise_for_status()
            for e in r.json().get("data", []):
                if e.get("ioc_type") not in ("url", "domain"):
                    continue
                records.append({
                    "source":     "threatfox",
                    "url":        e.get("ioc",""),
                    "status":     "unknown",
                    "date_added": e.get("first_seen",""),
                    "threat":     e.get("threat_type_desc",""),
                    "tags":       "|".join(e.get("tags") or []),
                    "host":       "",
                    "country_code": "",
                })
    except requests.exceptions.HTTPError as e3:
        errs.append(f"ThreatFox HTTP: {e3}")
    except Exception as e3:
        errs.append(f"ThreatFox: {e3}")

    if errs and records:
        st.info(f"ℹ️ Partial fetch — continuing with available data. ({errs[0][:100]})")

    if not records:
        st.warning("🔒 All live APIs blocked (school firewall). Using realistic synthetic data.")
        return make_synthetic(), "SYNTHETIC DATA"

    df = pd.DataFrame(records)
    for col in REQUIRED:
        if col not in df.columns: df[col] = ""
    return enrich(df), "LIVE FEED"


# ══════════════════════════════════════════════════════════════
#  SIDEBAR
# ══════════════════════════════════════════════════════════════

# ─── sidebar helper ──────────────────────────────────────────
def _slabel(txt, mt=14):
    st.markdown(
        f"<p style=\'font-family:IBM Plex Mono,monospace;font-size:.62rem;"
        f"letter-spacing:2px;color:#3a6080;text-transform:uppercase;"
        f"margin:{mt}px 0 4px;border-left:2px solid #1a3060;padding-left:8px;\'>"
        f"{txt}</p>",
        unsafe_allow_html=True,
    )

with st.sidebar:
    st.markdown("""
    <div style='padding:20px 12px 14px;background:linear-gradient(180deg,#060f1e,#04070f);
                border-bottom:1px solid #112244;margin:-1rem -1rem 0;'>
      <div style='font-family:Orbitron,sans-serif;font-size:1.1rem;font-weight:900;
                  background:linear-gradient(90deg,#7dd3fc,#ff4f2b,#fbbf24);
                  -webkit-background-clip:text;-webkit-text-fill-color:transparent;
                  background-clip:text;letter-spacing:5px;text-align:center;'>THREATSCOPE</div>
      <div style='font-family:IBM Plex Mono,monospace;font-size:0.55rem;color:#1a3050;
                  letter-spacing:4px;text-align:center;margin-top:3px;'>PHISHING OBSERVATORY</div>
      <div style='margin-top:10px;height:1px;
                  background:linear-gradient(90deg,transparent,#1a3060,transparent);'></div>
    </div>""", unsafe_allow_html=True)

    nowstr = datetime.now(timezone.utc).strftime("%H:%M UTC")
    st.markdown(f"""
    <div style='display:flex;align-items:center;gap:8px;padding:10px 4px 4px;
                font-family:IBM Plex Mono,monospace;font-size:0.65rem;color:#3a6080;'>
      <span style='width:7px;height:7px;border-radius:50%;background:#2dd4bf;
                   display:inline-block;animation:orbPulse 2s ease infinite;'></span>
      SYSTEM ONLINE &nbsp;&#183;&nbsp; {nowstr}
    </div>""", unsafe_allow_html=True)

    st.divider()

    _slabel("Actions", mt=0)
    col_r, col_c = st.columns(2)
    with col_r:
        if st.button("⟳ Refresh", use_container_width=True):
            st.cache_data.clear()
            st.rerun()
    with col_c:
        if st.button("✕ Clear", use_container_width=True):
            st.cache_data.clear()
            st.rerun()

    _slabel("Data Sources")
    src_urlhaus   = st.checkbox("URLhaus",   value=True)
    src_threatfox = st.checkbox("ThreatFox", value=True)
    sel_srcs = []
    if src_urlhaus:   sel_srcs.append("urlhaus")
    if src_threatfox: sel_srcs.append("threatfox")
    if not sel_srcs:  sel_srcs = ["urlhaus", "threatfox"]

    _slabel("Date Range")
    use_date = st.toggle("Filter by date", value=False)

    _slabel("URL Status Filter")
    show_online  = st.checkbox("Online",  value=True, key="f_on")
    show_offline = st.checkbox("Offline", value=True, key="f_off")
    show_unknown = st.checkbox("Unknown", value=True, key="f_unk")

    _slabel("Threat Type Keyword")
    threat_filter = st.text_input("Threat keyword", "", placeholder="e.g. phishing",
                                  label_visibility="collapsed")

    _slabel("Chart Controls")
    top_tld  = st.slider("Top TLDs",      5, 25, 15)
    top_tags = st.slider("Top Tags",      5, 30, 15)
    top_host = st.slider("Top Hosts",     5, 20, 10)
    top_ctry = st.slider("Top Countries", 3, 15,  8)

    _slabel("Colour Scale")
    chart_scale = st.selectbox("Scale", ["Plasma","Viridis","Turbo","Inferno","Cividis"],
                               index=0, label_visibility="collapsed")

    st.divider()
    st.markdown("""
    <div style='background:#060d1a;border:1px solid #112244;border-radius:8px;
                padding:12px 14px;font-family:IBM Plex Mono,monospace;font-size:0.6rem;
                line-height:2;color:#2a5070;'>
      <div style='color:#3a6080;font-size:0.62rem;margin-bottom:4px;letter-spacing:2px;'>
        DATA SOURCES</div>
      <div>URLhaus &mdash; abuse.ch CSV feed</div>
      <div>ThreatFox &mdash; abuse.ch IOC API</div>
      <div style='margin-top:6px;color:#1a3050;'>
        Cache TTL: 3600s &nbsp;|&nbsp; No URLs visited</div>
    </div>""", unsafe_allow_html=True)

    with st.expander("About this app"):
        st.markdown("""
        <div style='font-family:IBM Plex Mono,monospace;font-size:0.68rem;
                    color:#3a6080;line-height:1.8;'>
        <b style='color:#7dd3fc;'>ThreatScope Observatory</b><br>
        Academy Phishing URL Analysis<br><br>
        Tabs: Overview | Infrastructure<br>
        Timeline | Threats | Inspector | Raw Intel<br><br>
        No URLs are visited or resolved.
        </div>""", unsafe_allow_html=True)


# ══════════════════════════════════════════════════════════════
#  LOAD & FILTER
# ══════════════════════════════════════════════════════════════

with st.spinner(""):
    df_all, data_src = load_data()

df = df_all[df_all["source"].isin(sel_srcs)].copy() if not df_all.empty else empty_df()

# ── Apply sidebar status filter ────────────────────────────────
if "status" in df.columns:
    allowed = []
    if show_online:  allowed.append("online")
    if show_offline: allowed.append("offline")
    if show_unknown: allowed.append("unknown")
    df = df[df["status"].isin(allowed) | ~df["status"].isin(["online","offline","unknown"])]

# ── Apply threat keyword filter ─────────────────────────────────
if threat_filter.strip() and "threat" in df.columns:
    df = df[df["threat"].astype(str).str.contains(threat_filter.strip(), case=False, na=False) |
            df["tags"].astype(str).str.contains(threat_filter.strip(), case=False, na=False)]

# ── Apply date filter ───────────────────────────────────────────
if use_date and "date_added" in df.columns and df["date_added"].notna().any():
    mn = df["date_added"].min().date()
    mx = df["date_added"].max().date()
    dr = st.sidebar.date_input("Range", value=(mn, mx), min_value=mn, max_value=mx)
    if len(dr) == 2:
        df = df[(df["date_added"] >= pd.Timestamp(dr[0], tz="UTC")) &
                (df["date_added"] <= pd.Timestamp(dr[1], tz="UTC"))]


# ══════════════════════════════════════════════════════════════
#  HEADER
# ══════════════════════════════════════════════════════════════

st.markdown(f"""
<div style='margin-bottom:6px;'>
  <div class='obs-title'>🔭 ThreatScope Observatory</div>
  <div class='obs-sub'>
    <span class='orb'></span>
    PHISHING URL INTELLIGENCE &nbsp;·&nbsp; {data_src} &nbsp;·&nbsp;
    {datetime.now(timezone.utc).strftime('%Y-%m-%d  %H:%M UTC')}
  </div>
</div>
""", unsafe_allow_html=True)

if df_all.empty or len(df) == 0:
    st.error("No data. Run `python phishing_analysis.py` first or press Refresh.")
    st.stop()


# ══════════════════════════════════════════════════════════════
#  KPI ROW
# ══════════════════════════════════════════════════════════════

n_total  = len(df)
n_online = int((df.get("status","") == "online").sum())
n_hosts  = int(df["host"].nunique()) if "host" in df.columns else 0
n_tlds   = int(df["tld"].nunique()) if "tld" in df.columns else 0
n_ctry   = int(df["country_code"].nunique()) if "country_code" in df.columns else 0
overlap  = df.groupby("url")["source"].apply(set)
n_ovl    = int((overlap.apply(len) > 1).sum())
online_p = n_online / max(n_total, 1) * 100

k1,k2,k3,k4,k5,k6 = st.columns(6)
k1.metric("Total URLs",         f"{n_total:,}")
k2.metric("Still Online",       f"{n_online:,}", delta=f"{online_p:.0f}% active", delta_color="inverse")
k3.metric("Unique Hosts",       f"{n_hosts:,}")
k4.metric("Cross-Feed Overlap", f"{n_ovl:,}")
k5.metric("Distinct TLDs",      f"{n_tlds:,}")
k6.metric("Countries",          f"{n_ctry:,}")

# Ticker
all_tags_tick = []
for ts in df["tags"].dropna():
    all_tags_tick.extend(t.strip() for t in str(ts).split("|") if t.strip())
top_tick = [t for t,_ in Counter(all_tags_tick).most_common(8)]
ticker_html = "".join(f"<span class='tick'>⚡ ACTIVE: <b>{t}</b></span>" for t in top_tick)
ticker_html += f"<span class='tick'>📡 TOTAL: <b>{n_total:,}</b></span>"
ticker_html += f"<span class='tick'>🔴 ONLINE: <b>{n_online:,}</b></span>"
ticker_html += f"<span class='tick'>🌐 HOSTS: <b>{n_hosts:,}</b></span>"
st.markdown(f"<div class='ticker-outer'><div class='ticker-track'>{ticker_html}</div></div>", unsafe_allow_html=True)

st.divider()


# ══════════════════════════════════════════════════════════════
#  TABS
# ══════════════════════════════════════════════════════════════

tab1, tab2, tab3, tab4, tab5, tab6 = st.tabs([
    "📊  Overview",
    "🌐  Infrastructure",
    "⏱  Timeline",
    "☣  Threats",
    "🔍  Inspector",
    "📋  Raw Intel",
])

# ─── shared legend style ─────────────────────────────────────
LEG = dict(font=dict(family="IBM Plex Mono", color=C_TEXT, size=10),
           bgcolor=C_CARD, bordercolor=C_BORD)
TITLE_FONT = dict(family="Orbitron, sans-serif", size=13, color=C_ICE)


# ══════════════════════════════════════════════════════════════
#  TAB 1 — OVERVIEW
# ══════════════════════════════════════════════════════════════

with tab1:
    st.markdown("<div class='sec-head'>Finding 1 — URL Status, Protocol & Complexity</div>", unsafe_allow_html=True)
    c1, c2, c3 = st.columns(3)

    # Status donut
    with c1:
        uh = df[df["source"] == "urlhaus"]
        if not uh.empty and "status" in uh.columns:
            cnts = uh["status"].value_counts().reset_index()
            cnts.columns = ["status","count"]
            pal  = {"online": C_ORG, "offline": C_MUTED, "unknown": C_GOLD}
            cols = [pal.get(s, C_ICE) for s in cnts["status"]]
            fig  = go.Figure(go.Pie(
                labels=cnts["status"], values=cnts["count"], hole=0.55,
                marker=dict(colors=cols, line=dict(color=C_BG, width=3)),
                textfont=dict(family="IBM Plex Mono", color=C_TEXT, size=11),
                hovertemplate="<b>%{label}</b><br>Count: %{value:,}<br>%{percent}<extra></extra>",
            ))
            fig.add_annotation(text=f"<b>{n_online:,}</b><br>online",
                               x=0.5, y=0.5, showarrow=False,
                               font=dict(color=C_ORG, size=16, family="Orbitron"))
            fig.update_layout(**plotly_base(title="URL Status (URLhaus)", title_x=0.5,
                title_font=TITLE_FONT, showlegend=True, legend=LEG, height=300))
            st.plotly_chart(fig, width="stretch")

    # Protocol bar
    with c2:
        if "scheme" in df.columns:
            sc = df["scheme"].value_counts().reset_index()
            sc.columns = ["scheme","count"]
            pal2 = {"http": C_ORG, "https": C_TEAL}
            c2l  = [pal2.get(s, C_ICE) for s in sc["scheme"]]
            fig  = go.Figure(go.Bar(
                x=sc["scheme"], y=sc["count"],
                marker=dict(color=c2l, line=dict(color=C_BG, width=2)),
                text=sc["count"].apply(lambda v: f"{v:,}"),
                textposition="outside", textfont=dict(color=C_TEXT, size=10),
                hovertemplate="<b>%{x}</b><br>%{y:,} URLs<extra></extra>",
            ))
            fig.update_layout(**plotly_base(title="Protocol Distribution", title_x=0.5,
                title_font=TITLE_FONT, yaxis_title="URLs", height=300))
            st.plotly_chart(fig, width="stretch")

    # Risk gauge — FIX: all step colors use plain rgba(), never 8-digit hex
    with c3:
        risk_val = min(int(online_p * 1.3), 100)
        gc = C_ORG if risk_val > 50 else (C_GOLD if risk_val > 25 else C_TEAL)
        fig = go.Figure(go.Indicator(
            mode="gauge+number+delta",
            value=risk_val,
            delta={"reference": 50, "valueformat": ".0f"},
            title={"text": "Live Threat Level", "font": {"family":"Orbitron","color":C_ICE,"size":12}},
            number={"font":{"family":"Orbitron","color":gc,"size":34},"suffix":"%"},
            gauge={
                "axis": {"range":[0,100],"tickwidth":1,"tickcolor":C_BORD,
                         "tickfont":{"color":C_TEXT,"size":8}},
                "bar":  {"color": gc, "thickness": 0.25},
                "bgcolor": C_CARD,
                "borderwidth": 1,
                "bordercolor": C_BORD,
                # ✅ Use rgba() — Plotly rejects 8-digit hex like #ff4f2b33
                "steps": [
                    {"range": [0,  25], "color": rgba(C_TEAL, 0.18)},
                    {"range": [25, 60], "color": rgba(C_GOLD, 0.18)},
                    {"range": [60,100], "color": rgba(C_ORG,  0.18)},
                ],
                "threshold": {"line":{"color":C_ORG,"width":3},"thickness":0.75,"value":75},
            }
        ))
        fig.update_layout(paper_bgcolor=C_PAPER, plot_bgcolor=C_CARD,
                          font=dict(family="IBM Plex Mono",color=C_TEXT),
                          margin=dict(l=20,r=20,t=50,b=10), height=300)
        st.plotly_chart(fig, width="stretch")

    # Path depth + source split
    c1, c2 = st.columns([3,2])
    with c1:
        if "path_depth" in df.columns:
            pdc = df["path_depth"].value_counts().sort_index().reset_index()
            pdc.columns = ["depth","count"]
            med = int(df["path_depth"].median())
            fig = go.Figure(go.Bar(
                x=pdc["depth"], y=pdc["count"],  # numeric axis required for add_vline
                marker=dict(color=pdc["count"], colorscale=chart_scale,
                            line=dict(color=C_BG, width=1)),
                text=pdc["count"].apply(lambda v: f"{v:,}"),
                textposition="outside", textfont=dict(color=C_TEXT, size=9),
                hovertemplate="Depth %{x}: <b>%{y:,} URLs</b><extra></extra>",
            ))
            fig.add_vline(x=int(med), line_color=C_GOLD, line_dash="dash", line_width=2,
                          annotation_text=f"Median={med}",
                          annotation_font=dict(color=C_GOLD,size=10,family="IBM Plex Mono"))
            fig.update_layout(**plotly_base(title="URL Path Depth Distribution", title_x=0.5,
                title_font=TITLE_FONT, xaxis_title="Path Depth", yaxis_title="URLs", height=300))
            st.plotly_chart(fig, width="stretch")
    with c2:
        srcc = df["source"].value_counts().reset_index()
        srcc.columns = ["source","count"]
        fig = go.Figure(go.Pie(
            labels=srcc["source"], values=srcc["count"], hole=0.5,
            marker=dict(colors=[C_ICE, C_TEAL], line=dict(color=C_BG, width=3)),
            textfont=dict(family="IBM Plex Mono", color=C_TEXT, size=11),
            hovertemplate="<b>%{label}</b><br>%{value:,} (%{percent})<extra></extra>",
        ))
        fig.update_layout(**plotly_base(title="Source Split", title_x=0.5,
            title_font=TITLE_FONT, showlegend=True, legend=LEG, height=300))
        st.plotly_chart(fig, width="stretch")


# ══════════════════════════════════════════════════════════════
#  TAB 2 — INFRASTRUCTURE
# ══════════════════════════════════════════════════════════════

with tab2:
    st.markdown("<div class='sec-head'>Finding 2 — Infrastructure Fingerprint</div>", unsafe_allow_html=True)

    # TLD bar
    tld_c = df["tld"].value_counts().head(top_tld).reset_index()
    tld_c.columns = ["tld","count"]
    tld_c["pct"] = (tld_c["count"] / tld_c["count"].sum() * 100).round(1)
    fig = go.Figure(go.Bar(
        x=tld_c["count"], y=tld_c["tld"], orientation="h",
        marker=dict(color=tld_c["count"], colorscale=chart_scale,
                    line=dict(color=C_BG,width=1), showscale=True,
                    colorbar=dict(title=dict(text="Count", font=dict(color=C_TEXT)),tickfont=dict(color=C_TEXT,size=9),bgcolor=C_CARD,bordercolor=C_BORD)),
        text=[f"{v:,}  ({p}%)" for v,p in zip(tld_c["count"],tld_c["pct"])],
        textposition="outside", textfont=dict(color=C_TEXT,size=10),
        hovertemplate="<b>%{y}</b><br>%{x:,} URLs<extra></extra>",
    ))
    fig.update_layout(**plotly_base(title=f"Top {top_tld} TLDs Used in Malicious URLs", title_x=0.5,
        title_font=TITLE_FONT, xaxis_title="URL Count", height=480,
        yaxis=dict(autorange="reversed", gridcolor=C_BORD, linecolor=C_BORD)))
    st.plotly_chart(fig, width="stretch")

    c1, c2 = st.columns(2)
    with c1:
        ctry_c = df["country_code"].replace("",pd.NA).dropna().value_counts().head(top_ctry).reset_index()
        ctry_c.columns = ["country","count"]
        if not ctry_c.empty:
            fig = go.Figure(go.Bar(
                x=ctry_c["country"], y=ctry_c["count"],
                marker=dict(color=ctry_c["count"], colorscale="Viridis",
                            line=dict(color=C_BG,width=1)),
                text=ctry_c["count"].apply(lambda v: f"{v:,}"),
                textposition="outside", textfont=dict(color=C_TEXT,size=10),
                hovertemplate="<b>%{x}</b><br>%{y:,} URLs<extra></extra>",
            ))
            fig.update_layout(**plotly_base(title=f"Top {top_ctry} Hosting Countries", title_x=0.5,
                title_font=TITLE_FONT, yaxis_title="URLs", height=360))
            st.plotly_chart(fig, width="stretch")
        else:
            st.info("No country data — URLhaus only.")

    with c2:
        host_c = df["host"].replace("",pd.NA).dropna().value_counts().head(top_host).reset_index()
        host_c.columns = ["host","count"]
        if not host_c.empty:
            fig = go.Figure(go.Bar(
                x=host_c["count"], y=host_c["host"], orientation="h",
                marker=dict(color=C_ROSE, line=dict(color=C_BG,width=1), opacity=0.85),
                text=host_c["count"].apply(lambda v: f"{v:,}"),
                textposition="outside", textfont=dict(color=C_TEXT,size=9),
                hovertemplate="<b>%{y}</b><br>%{x:,} URLs<extra></extra>",
            ))
            fig.update_layout(**plotly_base(title=f"Top {top_host} Most-Abused Hosts", title_x=0.5,
                title_font=TITLE_FONT, xaxis_title="URL Count", height=360,
                yaxis=dict(autorange="reversed",gridcolor=C_BORD,linecolor=C_BORD,tickfont=dict(size=9))))
            st.plotly_chart(fig, width="stretch")

    # TLD treemap
    st.markdown("<div class='sec-head'>TLD Share — Treemap (click to zoom)</div>", unsafe_allow_html=True)
    tld_tree = df["tld"].value_counts().head(30).reset_index()
    tld_tree.columns = ["tld","count"]
    fig = px.treemap(tld_tree, path=["tld"], values="count",
                     color="count", color_continuous_scale="Plasma")
    fig.update_layout(paper_bgcolor=C_PAPER, font=dict(family="IBM Plex Mono",color=C_TEXT),
                      margin=dict(l=0,r=0,t=40,b=0), height=360,
                      title="TLD Treemap — Top 30", title_x=0.5,
                      title_font=dict(family="Orbitron",size=13,color=C_ICE),
                      coloraxis_colorbar=dict(tickfont=dict(color=C_TEXT), title=dict(font=dict(color=C_TEXT))))
    fig.update_traces(textfont=dict(family="IBM Plex Mono",size=11))
    st.plotly_chart(fig, width="stretch")


# ══════════════════════════════════════════════════════════════
#  TAB 3 — TIMELINE
# ══════════════════════════════════════════════════════════════

with tab3:
    st.markdown("<div class='sec-head'>Finding 3 — Temporal Activity & Burst Detection</div>", unsafe_allow_html=True)

    ts_df = df.dropna(subset=["date_added"]).copy()
    if not ts_df.empty:
        ts_df["day"] = ts_df["date_added"].dt.floor("D")
        daily = ts_df.groupby(["day","source"]).size().unstack(fill_value=0).reset_index()

        fig = go.Figure()
        pal_src = {"urlhaus": C_ICE, "threatfox": C_TEAL}
        for src in [c for c in daily.columns if c != "day"]:
            clr = pal_src.get(src, C_PURP)
            # ✅ fillcolor uses rgba() helper, not 8-digit hex concatenation
            fig.add_trace(go.Scatter(
                x=daily["day"], y=daily[src],
                name=src.upper(), mode="lines+markers",
                line=dict(color=clr, width=2.5),
                marker=dict(size=6, color=clr, line=dict(color=C_BG,width=1)),
                fill="tozeroy",
                fillcolor=rgba(clr, 0.08),
                hovertemplate=f"<b>{src.upper()}</b><br>%{{x|%Y-%m-%d}}<br>%{{y:,}} submissions<extra></extra>",
            ))

        # Peak annotation
        total_d = daily[[c for c in daily.columns if c!="day"]].sum(axis=1)
        if not total_d.empty:
            pk_i   = total_d.idxmax()
            pk_val = int(total_d.max())
            pk_day = daily.loc[pk_i,"day"]
            fig.add_vline(x=pk_day.isoformat() if hasattr(pk_day,"isoformat") else str(pk_day), line_color=C_GOLD, line_dash="dash", line_width=2)
            fig.add_annotation(x=pk_day.isoformat() if hasattr(pk_day,"isoformat") else str(pk_day), y=pk_val,
                               text=f" PEAK: {pk_val:,}",
                               showarrow=True, arrowhead=2, arrowcolor=C_GOLD,
                               font=dict(color=C_GOLD,size=11,family="IBM Plex Mono"),
                               bgcolor=C_CARD, bordercolor=C_GOLD, ax=40, ay=-40)

        fig.update_layout(**plotly_base(
            title="Daily URL Submission Rate", title_x=0.5, title_font=TITLE_FONT,
            xaxis_title="Date", yaxis_title="Submissions / Day",
            legend=LEG, height=420,
            xaxis=dict(
                rangeslider=dict(visible=True, bgcolor=C_CARD, bordercolor=C_BORD, thickness=0.07),
                gridcolor=C_BORD, linecolor=C_BORD,
            ),
        ))
        st.plotly_chart(fig, width="stretch")

        # Hourly heatmap
        st.markdown("<div class='sec-head'>Hourly Activity Heatmap — Day × Hour</div>", unsafe_allow_html=True)
        ts_df["hour"] = ts_df["date_added"].dt.hour
        ts_df["dow"]  = ts_df["date_added"].dt.day_name()
        dow_order = ["Monday","Tuesday","Wednesday","Thursday","Friday","Saturday","Sunday"]
        heat = ts_df.groupby(["dow","hour"]).size().reset_index(name="count")
        heat["dow"] = pd.Categorical(heat["dow"], categories=dow_order, ordered=True)
        heat = heat.sort_values("dow")
        fig = px.density_heatmap(heat, x="hour", y="dow", z="count",
                                  color_continuous_scale="Inferno",
                                  labels={"hour":"Hour (UTC)","dow":"","count":"URLs"})
        fig.update_layout(paper_bgcolor=C_PAPER, plot_bgcolor=C_CARD,
                          font=dict(family="IBM Plex Mono",color=C_TEXT,size=10),
                          margin=dict(l=10,r=10,t=44,b=10), height=300,
                          title="Submissions by Day & Hour (UTC)", title_x=0.5,
                          title_font=dict(family="Orbitron",size=13,color=C_ICE),
                          coloraxis_colorbar=dict(tickfont=dict(color=C_TEXT), title=dict(font=dict(color=C_TEXT))))
        st.plotly_chart(fig, width="stretch")
    else:
        st.info("No timestamp data available.")


# ══════════════════════════════════════════════════════════════
#  TAB 4 — THREATS
# ══════════════════════════════════════════════════════════════

with tab4:
    st.markdown("<div class='sec-head'>Finding 4 — Malware Families & Threat Intelligence</div>", unsafe_allow_html=True)

    all_tags = []
    for ts in df["tags"].dropna():
        all_tags.extend(t.strip() for t in str(ts).split("|") if t.strip())
    for thr in df["threat"].dropna():
        if str(thr).strip(): all_tags.append(str(thr).strip())

    c1, c2 = st.columns([3,2])

    with c1:
        if all_tags:
            tagc = pd.Series(dict(Counter(all_tags).most_common(top_tags))).reset_index()
            tagc.columns = ["tag","count"]
            fig = go.Figure(go.Bar(
                x=tagc["count"], y=tagc["tag"], orientation="h",
                marker=dict(color=tagc["count"], colorscale="YlOrRd",
                            line=dict(color=C_BG,width=1), showscale=True,
                            colorbar=dict(title=dict(text="Count", font=dict(color=C_TEXT)),tickfont=dict(color=C_TEXT,size=9),bgcolor=C_CARD,bordercolor=C_BORD)),
                text=tagc["count"].apply(lambda v: f"{v:,}"),
                textposition="outside", textfont=dict(color=C_TEXT,size=10),
                hovertemplate="<b>%{y}</b><br>%{x:,} occurrences<extra></extra>",
            ))
            fig.update_layout(**plotly_base(
                title=f"Top {top_tags} Threat Tags / Malware Families", title_x=0.5,
                title_font=TITLE_FONT, xaxis_title="Occurrences", height=520,
                yaxis=dict(autorange="reversed",gridcolor=C_BORD,linecolor=C_BORD,tickfont=dict(size=9))))
            st.plotly_chart(fig, width="stretch")

    with c2:
        thr_c = df["threat"].replace("",pd.NA).dropna().value_counts().reset_index()
        thr_c.columns = ["threat","count"]
        if not thr_c.empty:
            fig = go.Figure(go.Pie(
                labels=thr_c["threat"], values=thr_c["count"], hole=0.45,
                marker=dict(
                    colors=[C_ORG,C_GOLD,C_PURP,C_TEAL,C_LIME,C_ROSE,C_ICE][:len(thr_c)],
                    line=dict(color=C_BG,width=2)),
                textfont=dict(family="IBM Plex Mono",color=C_TEXT,size=10),
                hovertemplate="<b>%{label}</b><br>%{value:,} (%{percent})<extra></extra>",
            ))
            fig.update_layout(**plotly_base(title="Threat Types", title_x=0.5,
                title_font=TITLE_FONT, showlegend=True, legend=LEG, height=280))
            st.plotly_chart(fig, width="stretch")

        total_uniq = len(overlap); n_multi = int((overlap.apply(len)>1).sum())
        ovl_pct = n_multi/max(total_uniq,1)*100
        st.markdown(f"""
        <div style='background:#0a1628;border:1px solid #112244;border-radius:10px;
                    padding:18px 20px;margin-top:8px;'>
          <div style='font-family:Orbitron,sans-serif;font-size:0.72rem;color:#7dd3fc;
                      letter-spacing:2px;text-transform:uppercase;margin-bottom:10px;'>
            Cross-Source Overlap</div>
          <div style='font-family:IBM Plex Mono,monospace;font-size:0.78rem;
                      color:#e0f0ff;line-height:2.2;'>
            Unique URLs: <b style='color:#7dd3fc'>{total_uniq:,}</b><br>
            In 2+ feeds: <b style='color:#fbbf24'>{n_multi:,}</b><br>
            Overlap rate: <b style='color:#ff4f2b'>{ovl_pct:.2f}%</b>
          </div>
        </div>""", unsafe_allow_html=True)

    # Sunburst
    st.markdown("<div class='sec-head'>Threat Hierarchy Sunburst — click to drill down</div>", unsafe_allow_html=True)
    sun_rows = []
    for _, row in df.iterrows():
        thr = str(row.get("threat","")).strip() or "unknown"
        for tag in str(row.get("tags","")).split("|"):
            tag = tag.strip()
            if tag: sun_rows.append({"threat":thr,"tag":tag})
    if sun_rows:
        sdf = pd.DataFrame(sun_rows).value_counts().reset_index()
        sdf.columns = ["threat","tag","count"]
        fig = px.sunburst(sdf.head(120), path=["threat","tag"], values="count",
                          color="count", color_continuous_scale="Turbo")
        fig.update_layout(paper_bgcolor=C_PAPER,
                          font=dict(family="IBM Plex Mono",color=C_TEXT,size=10),
                          margin=dict(l=0,r=0,t=44,b=0), height=460,
                          title="Threat Type → Malware Family", title_x=0.5,
                          title_font=dict(family="Orbitron",size=12,color=C_ICE),
                          coloraxis_colorbar=dict(tickfont=dict(color=C_TEXT), title=dict(font=dict(color=C_TEXT))))
        st.plotly_chart(fig, width="stretch")


# ══════════════════════════════════════════════════════════════
#  TAB 5 — URL INSPECTOR
# ══════════════════════════════════════════════════════════════

with tab5:
    st.markdown("<div class='sec-head'>URL Risk Inspector — structural analysis (never visits URLs)</div>", unsafe_allow_html=True)
    st.markdown("""
    <p style='font-family:IBM Plex Mono,monospace;font-size:0.75rem;color:#2a5070;margin-bottom:14px;'>
    Paste any suspicious URL for structural/lexical risk scoring.
    <b style='color:#ff4f2b'>This tool never fetches or visits URLs.</b>
    </p>""", unsafe_allow_html=True)

    url_in = st.text_input("", placeholder="https://suspicious-domain.xyz/login/verify.php",
                            label_visibility="collapsed")

    if url_in.strip():
        risk, flags = score_risk(url_in.strip())
        parsed = urlparse(url_in.strip())
        tldv   = extract_tld(url_in.strip())
        depth  = len([p for p in parsed.path.split("/") if p])
        host   = parsed.hostname or "N/A"
        scheme = parsed.scheme or "N/A"

        if risk >= 65:   badge,label = "b-crit","CRITICAL"
        elif risk >= 40: badge,label = "b-high","HIGH"
        elif risk >= 20: badge,label = "b-med","MEDIUM"
        else:            badge,label = "b-low","LOW"

        gc = C_ORG if risk>50 else (C_GOLD if risk>25 else C_TEAL)

        c1, c2 = st.columns([1,2])
        with c1:
            # ✅ Gauge steps with rgba() — no 8-digit hex
            fig = go.Figure(go.Indicator(
                mode="gauge+number",
                value=risk,
                title={"text":"Risk Score","font":{"family":"Orbitron","color":C_ICE,"size":12}},
                number={"font":{"family":"Orbitron","color":gc,"size":40},"suffix":"/100"},
                gauge={
                    "axis":{"range":[0,100],"tickwidth":1,"tickcolor":C_BORD,
                             "tickfont":{"color":C_TEXT,"size":8}},
                    "bar":{"color":gc,"thickness":0.28},
                    "bgcolor":C_CARD, "borderwidth":1, "bordercolor":C_BORD,
                    "steps":[
                        {"range":[0, 20],  "color": rgba(C_TEAL, 0.15)},
                        {"range":[20, 40], "color": rgba(C_LIME, 0.12)},
                        {"range":[40, 65], "color": rgba(C_GOLD, 0.15)},
                        {"range":[65,100], "color": rgba(C_ORG,  0.15)},
                    ],
                }
            ))
            fig.update_layout(paper_bgcolor=C_PAPER, plot_bgcolor=C_CARD,
                              font=dict(family="IBM Plex Mono",color=C_TEXT),
                              margin=dict(l=20,r=20,t=50,b=20), height=280)
            st.plotly_chart(fig, width="stretch")
            st.markdown(f"<div style='text-align:center;padding:6px;'><span class='{badge}'>{label} RISK</span></div>", unsafe_allow_html=True)

        with c2:
            sc_color = "#ff4f2b" if scheme=="http" else "#2dd4bf"
            st.markdown(f"""
            <div class='icard'>
              <div style='font-family:Orbitron,sans-serif;font-size:0.75rem;color:#7dd3fc;
                          letter-spacing:2px;text-transform:uppercase;margin-bottom:12px;'>
                Structural Breakdown
              </div>
              <div class='irow'><span class='ikey'>SCHEME</span>
                <span class='ival' style='color:{sc_color};'>{scheme.upper()}</span></div>
              <div class='irow'><span class='ikey'>HOST</span>
                <span class='ival'>{host}</span></div>
              <div class='irow'><span class='ikey'>TLD</span>
                <span class='ival'>{tldv}</span></div>
              <div class='irow'><span class='ikey'>PATH</span>
                <span class='ival'>{parsed.path or "/"}</span></div>
              <div class='irow'><span class='ikey'>DEPTH</span>
                <span class='ival'>{depth} levels</span></div>
              <div class='irow'><span class='ikey'>QUERY</span>
                <span class='ival'>{parsed.query or "none"}</span></div>
              <div class='irow'><span class='ikey'>HOST LENGTH</span>
                <span class='ival'>{len(host)} chars</span></div>
            </div>""", unsafe_allow_html=True)

            if flags:
                st.markdown("""<div style='font-family:IBM Plex Mono,monospace;font-size:0.68rem;
                    color:#2a5070;letter-spacing:2px;text-transform:uppercase;margin:10px 0 6px;'>
                    Risk Indicators Detected</div>""", unsafe_allow_html=True)
                for f in flags:
                    st.markdown(f"<div style='font-family:IBM Plex Mono;font-size:0.75rem;color:#ff4f2b;padding:3px 0;'>⚠  {f}</div>", unsafe_allow_html=True)
            else:
                st.markdown("<div style='font-family:IBM Plex Mono;font-size:0.75rem;color:#2dd4bf;padding:8px 0;'>✓ No structural risk indicators detected</div>", unsafe_allow_html=True)

        # Dataset lookup
        if "url" in df.columns and host != "N/A":
            hits = df[df["url"].str.contains(host, case=False, na=False)]
            if not hits.empty:
                st.markdown(f"""
                <div style='background:rgba(255,79,43,0.06);border:1px solid rgba(255,79,43,0.35);
                            border-radius:8px;padding:12px 16px;margin-top:10px;'>
                  <span style='font-family:IBM Plex Mono;font-size:0.75rem;color:#ff4f2b;'>
                  ⚠  HOST FOUND IN THREAT DATABASE — {len(hits):,} matching URL(s)
                  </span>
                </div>""", unsafe_allow_html=True)
                st.dataframe(hits[["source","url","status","threat","tags"]].head(5), width="stretch")
            else:
                st.markdown("""
                <div style='background:rgba(45,212,191,0.05);border:1px solid rgba(45,212,191,0.3);
                            border-radius:8px;padding:12px 16px;margin-top:10px;'>
                  <span style='font-family:IBM Plex Mono;font-size:0.75rem;color:#2dd4bf;'>
                  ✓ Host not found in current dataset snapshot
                  </span>
                </div>""", unsafe_allow_html=True)
    else:
        st.markdown("""
        <div style='background:#0a1628;border:1px dashed #112244;border-radius:10px;
                    padding:48px;text-align:center;margin-top:10px;'>
          <div style='font-family:IBM Plex Mono,monospace;font-size:0.75rem;color:#1a3050;
                      letter-spacing:3px;'>AWAITING URL INPUT</div>
          <div style='font-family:IBM Plex Mono,monospace;font-size:0.62rem;color:#0d2030;
                      letter-spacing:2px;margin-top:8px;'>paste a suspicious url above to begin analysis</div>
        </div>""", unsafe_allow_html=True)


# ══════════════════════════════════════════════════════════════
#  TAB 6 — RAW INTEL
# ══════════════════════════════════════════════════════════════

with tab6:
    st.markdown("<div class='sec-head'>Raw Threat Intelligence Feed</div>", unsafe_allow_html=True)

    cf1, cf2, cf3 = st.columns(3)
    with cf1: q_url    = st.text_input("Search URL / host / keyword", "", placeholder="e.g. paypal, .xyz")
    with cf2: q_src    = st.selectbox("Source", ["All"] + list(df["source"].unique()))
    with cf3: q_status = st.selectbox("Status", ["All","online","offline","unknown"])

    show_cols = [c for c in ["source","url","status","date_added","threat","tags","tld","country_code","path_depth"] if c in df.columns]
    view = df[show_cols].copy()
    if q_url:
        mask = view.apply(lambda col: col.astype(str).str.contains(q_url, case=False, na=False)).any(axis=1)
        view = view[mask]
    if q_src != "All":
        view = view[view["source"] == q_src]
    if q_status != "All" and "status" in view.columns:
        view = view[view["status"] == q_status]

    st.caption(f"Showing {len(view):,} of {len(df):,} total rows")
    st.dataframe(view.head(2000), width="stretch")

    dc1, dc2 = st.columns(2)
    with dc1:
        st.download_button("⬇  Download filtered CSV",
                           data=view.to_csv(index=False).encode("utf-8"),
                           file_name="threatscope_export.csv", mime="text/csv")
    with dc2:
        rp = f"{OUTPUT_DIR}/summary_findings.txt"
        if os.path.exists(rp):
            with open(rp, "r", encoding="utf-8") as f:
                rtxt = f.read()
            st.download_button("⬇  Download Analysis Report",
                               data=rtxt.encode("utf-8"),
                               file_name="phishing_report.txt", mime="text/plain")


# ── Footer ─────────────────────────────────────────────────────
st.markdown(f"""
<div style='text-align:center;padding:32px 0 8px;
            font-family:IBM Plex Mono,monospace;font-size:0.58rem;
            color:#0d2030;letter-spacing:3px;text-transform:uppercase;'>
  THREATSCOPE OBSERVATORY &nbsp;·&nbsp; PHISHING URL INTELLIGENCE PLATFORM &nbsp;·&nbsp;
  {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}
</div>""", unsafe_allow_html=True)
