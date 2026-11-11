"""
CyberScraper - threat intelligence console.

Run from this folder (so the theme in .streamlit/config.toml loads):
    streamlit run dashboard.py
"""

import html
import json
from datetime import datetime, timedelta, timezone

import altair as alt
import pandas as pd
import streamlit as st

import rules_scraper as rs

st.set_page_config(page_title="CyberScraper · Threat Intelligence", page_icon=":material/shield:",
                   layout="wide", initial_sidebar_state="expanded")

# ==========================================
# 1. DESIGN TOKENS & STYLE
# ==========================================
# Severity is a state, so it uses the reserved status colours - always next to a text label.
SEVERITY_COLORS = {"Critical": "#d03b3b", "High": "#ec835a", "Medium": "#fab219", "Low": "#898781"}
GOOD = "#0ca30c"
ACCENT = "#3987e5"
SURFACE, SURFACE_2, PAGE = "#1a1a19", "#222220", "#0d0d0d"
INK, INK_2, MUTED = "#f0efec", "#c3c2b7", "#898781"
HAIRLINE, BASELINE = "#2c2c2a", "#383835"

st.markdown(f"""
<style>
  .block-container {{ padding-top: 1.4rem; padding-bottom: 3rem; max-width: 1440px; }}
  [data-testid="stSidebar"] {{ border-right: 1px solid {HAIRLINE}; }}
  [data-testid="stSidebar"] .block-container {{ padding-top: 1.5rem; }}
  [data-testid="stHeader"] {{ background: transparent; }}

  /* app bar */
  .brand {{ display: flex; align-items: center; gap: 12px; }}
  .brand-mark {{ width: 38px; height: 38px; border-radius: 9px; background: #1c2a3d;
                 display: grid; place-items: center; border: 1px solid #25405f; }}
  .brand-name {{ font-size: 1.25rem; font-weight: 700; color: {INK}; letter-spacing: -0.01em; line-height: 1.1; }}
  .brand-sub {{ font-size: 0.78rem; color: {MUTED}; letter-spacing: 0.04em; text-transform: uppercase; margin-top: 2px; }}
  .sync {{ display: flex; align-items: center; gap: 8px; justify-content: flex-end; font-size: 0.8rem; color: {MUTED}; }}
  .sync .live {{ width: 7px; height: 7px; border-radius: 50%; background: {GOOD}; box-shadow: 0 0 0 3px rgba(12,163,12,0.18); }}

  /* posture banner */
  .posture {{ display: flex; align-items: center; gap: 16px; flex-wrap: wrap; margin: 14px 0 18px 0;
              padding: 12px 18px; border-radius: 10px; background: {SURFACE};
              border: 1px solid {HAIRLINE}; border-left: 4px solid var(--c); }}
  .posture-label {{ font-size: 0.72rem; color: {MUTED}; letter-spacing: 0.08em; text-transform: uppercase; }}
  .posture-level {{ display: inline-flex; align-items: center; gap: 8px; font-weight: 700; color: {INK};
                    letter-spacing: 0.06em; text-transform: uppercase; font-size: 0.9rem; }}
  .posture-level .dot {{ width: 9px; height: 9px; border-radius: 50%; background: var(--c); }}
  .posture-text {{ color: {INK_2}; font-size: 0.88rem; }}

  /* KPI tiles */
  .kpis {{ display: grid; grid-template-columns: repeat(5, minmax(0, 1fr)); gap: 12px; margin-bottom: 8px; }}
  @media (max-width: 1000px) {{ .kpis {{ grid-template-columns: repeat(2, minmax(0, 1fr)); }} }}
  .kpi {{ background: {SURFACE}; border: 1px solid {HAIRLINE}; border-radius: 10px; padding: 14px 16px 12px 16px;
          border-top: 3px solid var(--c); }}
  .kpi-label {{ font-size: 0.72rem; color: {MUTED}; letter-spacing: 0.08em; text-transform: uppercase; }}
  .kpi-value {{ font-size: 1.9rem; font-weight: 650; color: {INK}; line-height: 1.2; margin: 4px 0 2px 0; }}
  .kpi-delta {{ font-size: 0.78rem; color: {INK_2}; }}
  .kpi-delta .muted {{ color: {MUTED}; }}

  /* section headings & panels */
  .section-title {{ font-size: 0.95rem; font-weight: 650; color: {INK}; margin: 0; }}
  .section-sub {{ font-size: 0.8rem; color: {MUTED}; margin: 2px 0 6px 0; }}
  [class*="st-key-panel_"] {{ background: {SURFACE}; border: 1px solid {HAIRLINE}; border-radius: 10px; padding: 16px 18px 8px 18px; }}

  /* article rows */
  [class*="st-key-card_"] {{ background: {SURFACE}; border: 1px solid {HAIRLINE}; border-left: 3px solid var(--sev, {MUTED});
                             border-radius: 8px; padding: 14px 18px 4px 18px; gap: 0.4rem; }}
  [class*="st-key-card_"]:hover {{ background: {SURFACE_2}; }}
  .meta {{ display: flex; flex-wrap: wrap; align-items: center; gap: 6px 14px; font-size: 0.74rem; color: {MUTED};
           letter-spacing: 0.04em; text-transform: uppercase; }}
  .sev {{ display: inline-flex; align-items: center; gap: 6px; font-weight: 700; color: {INK}; }}
  .sev .dot {{ width: 7px; height: 7px; border-radius: 50%; background: var(--c); }}
  .meta .src {{ color: {INK_2}; font-weight: 600; }}
  a.title {{ display: block; color: {INK} !important; text-decoration: none !important; font-size: 1.02rem;
             font-weight: 600; line-height: 1.4; margin: 6px 0 4px 0; }}
  a.title:hover {{ color: {ACCENT} !important; }}
  .summary {{ color: {INK_2}; font-size: 0.88rem; line-height: 1.55; margin: 0 0 8px 0;
              display: -webkit-box; -webkit-line-clamp: 2; -webkit-box-orient: vertical; overflow: hidden; }}
  .labels {{ display: flex; flex-wrap: wrap; gap: 6px; margin-bottom: 6px; }}
  .label {{ font-size: 0.72rem; padding: 1px 8px; border-radius: 4px; border: 1px solid {BASELINE}; color: {INK_2}; }}
  .label.cve {{ font-family: "JetBrains Mono", ui-monospace, Consolas, monospace; border-color: #25405f; color: #b7d3f6; }}
  [class*="st-key-card_"] [data-testid="stExpander"] details {{ border: none; }}
  [class*="st-key-card_"] [data-testid="stExpander"] summary {{ padding-left: 0; font-size: 0.8rem; color: {MUTED}; }}
  .pb-head {{ font-size: 0.8rem; font-weight: 650; color: {INK}; text-transform: uppercase; letter-spacing: 0.05em; margin: 4px 0 2px 0; }}
  .pb ol {{ margin: 0 0 10px 0; padding-left: 1.2rem; color: {INK_2}; font-size: 0.86rem; line-height: 1.55; }}

  .sidebar-foot {{ font-size: 0.75rem; color: {MUTED}; line-height: 1.5; margin-top: 8px; }}
</style>
""", unsafe_allow_html=True)


def esc(text) -> str:
    """Escape feed text for HTML. '$' is escaped too so Streamlit doesn't render it as LaTeX."""
    return html.escape(str(text or "")).replace("$", "&#36;")


def safe_url(url: str) -> str:
    url = str(url or "")
    return esc(url) if url.startswith(("http://", "https://")) else "#"


def time_ago(ts) -> str:
    if ts is None or pd.isna(ts):
        return "unknown"
    secs = (datetime.now(timezone.utc) - ts.to_pydatetime()).total_seconds()
    if secs < 3600:
        return f"{max(int(secs // 60), 1)}m ago"
    if secs < 86400:
        return f"{int(secs // 3600)}h ago"
    if secs < 86400 * 30:
        return f"{int(secs // 86400)}d ago"
    return ts.strftime("%d %b %Y")


# ==========================================
# 2. DATA
# ==========================================
def db_mtime() -> float:
    return rs.DB_PATH.stat().st_mtime if rs.DB_PATH.exists() else 0.0


@st.cache_data(show_spinner=False)
def load_data(_mtime: float) -> pd.DataFrame:
    """Cached until the database file changes (the mtime argument is the cache key)."""
    conn = rs.connect()  # also upgrades an old schema in place
    df = pd.read_sql_query("SELECT * FROM intel", conn)
    conn.close()
    if df.empty:
        return df
    df["published"] = pd.to_datetime(df["published_at"], utc=True, format="ISO8601", errors="coerce")
    df["fetched"] = pd.to_datetime(df["fetched_at"], utc=True, format="ISO8601", errors="coerce")
    df["severity"] = pd.Categorical(df["severity"].fillna("Low"), categories=rs.SEVERITY_LEVELS, ordered=True)
    df["threat_tags"] = df["threat_tags"].fillna("")
    df["tags"] = df["threat_tags"].apply(lambda s: [t for t in s.split(",") if t])
    df["ioc_dict"] = df["iocs"].apply(lambda s: json.loads(s) if s else {})
    df["cves"] = df["ioc_dict"].apply(lambda d: d.get("cve", []))
    df["ioc_count"] = df["ioc_dict"].apply(lambda d: sum(len(v) for k, v in d.items() if k != "cve"))
    return df.sort_values("published", ascending=False).reset_index(drop=True)


def refresh_feeds():
    with st.spinner("Fetching sources and extracting intelligence…"):
        st.session_state["last_refresh"] = rs.run(verbose=False)
    st.cache_data.clear()


df = load_data(db_mtime())
now = datetime.now(timezone.utc)

# ==========================================
# 3. APP BAR
# ==========================================
SHIELD_SVG = (f"<svg width='20' height='20' viewBox='0 0 24 24' fill='none' stroke='{ACCENT}' stroke-width='2' "
              "stroke-linecap='round' stroke-linejoin='round'><path d='M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z'/>"
              "<path d='M9 12l2 2 4-4'/></svg>")

bar_l, bar_m, bar_r = st.columns([2.2, 3, 1], vertical_alignment="center")
with bar_l:
    st.markdown(f"<div class='brand'><div class='brand-mark'>{SHIELD_SVG}</div><div>"
                f"<div class='brand-name'>CyberScraper</div>"
                f"<div class='brand-sub'>Threat Intelligence Console</div></div></div>", unsafe_allow_html=True)
with bar_m:
    if not df.empty:
        last_sync = df["fetched"].max()
        st.markdown(f"<div class='sync'><span class='live'></span>Last sync {last_sync:%d %b %Y, %H:%M} UTC "
                    f"({time_ago(last_sync)}) · {len(df):,} articles · {df['source'].nunique()} sources</div>",
                    unsafe_allow_html=True)
with bar_r:
    if st.button("Sync now", icon=":material/sync:", type="primary", width="stretch"):
        refresh_feeds()
        st.rerun()

if result := st.session_state.pop("last_refresh", None):
    st.toast(f"Sync complete: {result['new']} new articles ({result['fetched']} checked).", icon=":material/check_circle:")
    if result["failures"]:
        st.warning(f"{len(result['failures'])} source(s) could not be reached: " + ", ".join(result["failures"]),
                   icon=":material/warning:")

if df.empty:
    st.info("No intelligence collected yet. Select **Sync now** to fetch the first batch.", icon=":material/info:")
    st.stop()

# ==========================================
# 4. THREAT POSTURE (always last 24h, unfiltered)
# ==========================================
day = df[df["published"] >= now - timedelta(hours=24)]
crit24, high24 = int((day["severity"] == "Critical").sum()), int((day["severity"] == "High").sum())
if crit24 >= 5:
    level, color = "Severe", SEVERITY_COLORS["Critical"]
elif crit24 >= 1:
    level, color = "Elevated", SEVERITY_COLORS["High"]
elif high24 >= 3:
    level, color = "Guarded", SEVERITY_COLORS["Medium"]
else:
    level, color = "Low", GOOD
top_cat = day.explode("tags")["tags"].dropna().value_counts()
top_cat_txt = f" Most active category: <b>{esc(top_cat.index[0])}</b>." if not top_cat.empty else ""
st.markdown(
    f"<div class='posture' style='--c:{color}'><span class='posture-label'>Threat posture · 24h</span>"
    f"<span class='posture-level'><span class='dot'></span>{level}</span>"
    f"<span class='posture-text'>{crit24} critical and {high24} high-severity items reported in the last 24 hours.{top_cat_txt}</span></div>",
    unsafe_allow_html=True,
)

# ==========================================
# 5. SIDEBAR FILTERS
# ==========================================
WINDOWS = {"24h": 24, "7d": 24 * 7, "30d": 24 * 30, "All": None}
DEFAULTS = {"f_window": "7d", "f_search": "", "f_sev": ["Critical", "High", "Medium"],
            "f_tags": [], "f_src": [], "f_iocs": False, "f_page": 1}
for key, value in DEFAULTS.items():
    st.session_state.setdefault(key, value)


def reset_filters():
    for key, value in DEFAULTS.items():
        st.session_state[key] = value


with st.sidebar:
    st.markdown("<div class='section-title'>Filters</div><div class='section-sub'>Refine the intelligence shown</div>",
                unsafe_allow_html=True)
    st.segmented_control("Time window", list(WINDOWS), key="f_window", width="stretch")
    st.text_input("Search", key="f_search", placeholder="Keyword, CVE, IP or hash", icon=":material/search:")
    st.pills("Severity", rs.SEVERITY_LEVELS, selection_mode="multi", key="f_sev")
    st.multiselect("Threat category", sorted({t for tags in df["tags"] for t in tags}), key="f_tags",
                   placeholder="All categories")
    st.multiselect("Source", sorted(df["source"].unique()), key="f_src", placeholder="All sources")
    st.toggle("Only items with indicators", key="f_iocs")
    st.button("Reset filters", icon=":material/restart_alt:", on_click=reset_filters, width="stretch")
    st.divider()
    st.markdown(f"<div class='sidebar-foot'>{len(rs.FEEDS)} RSS sources monitored<br>"
                f"Stored locally in <code>{esc(rs.DB_PATH.name)}</code></div>", unsafe_allow_html=True)

ss = st.session_state
window_label = ss.f_window or "All"
hours = WINDOWS[window_label]

# Non-time filters first, so the previous period is compared like-for-like.
base = df
if ss.f_sev:
    base = base[base["severity"].isin(ss.f_sev)]
if ss.f_tags:
    base = base[base["tags"].apply(lambda ts: any(t in ts for t in ss.f_tags))]
if ss.f_src:
    base = base[base["source"].isin(ss.f_src)]
if ss.f_iocs:
    base = base[(base["ioc_count"] > 0) | (base["cves"].str.len() > 0)]
if ss.f_search:
    haystack = (base["title"].fillna("") + " " + base["summary"].fillna("") + " " +
                base["iocs"].fillna("") + " " + base["threat_tags"] + " " + base["source"])
    base = base[haystack.str.contains(ss.f_search, case=False, regex=False)]

if hours:
    start = now - timedelta(hours=hours)
    fdf = base[base["published"] >= start]
    prev = base[(base["published"] >= start - timedelta(hours=hours)) & (base["published"] < start)]
else:
    fdf, prev = base, None

# Back to page 1 whenever the filters change.
signature = (window_label, ss.f_search, tuple(ss.f_sev or []), tuple(ss.f_tags), tuple(ss.f_src), ss.f_iocs)
if ss.get("_sig") != signature:
    ss["_sig"] = signature
    ss.f_page = 1

# ==========================================
# 6. KPI TILES
# ==========================================
def metrics(frame: pd.DataFrame) -> dict:
    return {
        "articles": len(frame),
        "critical": int((frame["severity"] == "Critical").sum()),
        "high": int((frame["severity"] == "High").sum()),
        "cves": len({c for cves in frame["cves"] for c in cves}),
        "iocs": int(frame["ioc_count"].sum()),
    }


def delta_text(cur: int, before) -> str:
    if before is None:
        return "<span class='muted'>All time</span>"
    period = f"<span class='muted'>vs prior {window_label}</span>"
    if cur == before:
        return f"No change {period}"
    arrow = "▲" if cur > before else "▼"
    change = f"{abs(cur - before) / before:.0%}" if before else f"{cur - before:+d}"
    return f"{arrow} {change} {period}"


m, pm = metrics(fdf), (metrics(prev) if prev is not None else {})
tiles = [
    ("Articles", "articles", ACCENT),
    ("Critical", "critical", SEVERITY_COLORS["Critical"]),
    ("High", "high", SEVERITY_COLORS["High"]),
    ("Unique CVEs", "cves", BASELINE),
    ("Indicators", "iocs", BASELINE),
]
st.markdown(
    "<div class='kpis'>" + "".join(
        f"<div class='kpi' style='--c:{c}'><div class='kpi-label'>{label}</div>"
        f"<div class='kpi-value'>{m[key]:,}</div><div class='kpi-delta'>{delta_text(m[key], pm.get(key))}</div></div>"
        for label, key, c in tiles
    ) + "</div>",
    unsafe_allow_html=True,
)

tab_feed, tab_analytics, tab_iocs = st.tabs(
    [":material/article: Intelligence feed", ":material/monitoring: Analytics", ":material/fingerprint: Indicators"]
)

# ==========================================
# 7. INTELLIGENCE FEED
# ==========================================
PAGE_SIZE = 15


def render_row(row):
    sev = row["severity"]
    color = SEVERITY_COLORS.get(sev, MUTED)
    published = row["published"]
    stamp = published.strftime("%d %b %Y, %H:%M UTC") if pd.notna(published) else ""
    labels = "".join(f"<span class='label'>{esc(t)}</span>" for t in row["tags"])
    labels += "".join(f"<span class='label cve'>{esc(c)}</span>" for c in row["cves"][:6])
    if len(row["cves"]) > 6:
        labels += f"<span class='label'>+{len(row['cves']) - 6} more</span>"

    with st.container(key=f"card_{row['id']}"):
        st.markdown(f"<style>.st-key-card_{row['id']} {{ --sev: {color}; }}</style>"
                    f"<div class='meta'><span class='sev' style='--c:{color}'><span class='dot'></span>{esc(sev)}</span>"
                    f"<span class='src'>{esc(row['source'])}</span><span title='{esc(stamp)}'>{time_ago(published)}</span></div>"
                    f"<a class='title' href='{safe_url(row['url'])}' target='_blank' rel='noopener'>{esc(row['title'])}</a>"
                    f"<p class='summary'>{esc(row['summary'])}</p>"
                    + (f"<div class='labels'>{labels}</div>" if labels else ""),
                    unsafe_allow_html=True)

        iocs = {k: v for k, v in row["ioc_dict"].items() if v}
        if iocs or row["tags"]:
            parts = []
            if iocs:
                parts.append(f"{sum(len(v) for v in iocs.values())} indicators")
            if row["tags"]:
                parts.append("response playbook")
            with st.expander(" and ".join(parts).capitalize(), icon=":material/expand_circle_down:"):
                left, right = st.columns([1, 1.4], gap="large")
                with left:
                    st.markdown("<div class='pb-head'>Indicators of compromise</div>", unsafe_allow_html=True)
                    if iocs:
                        for ioc_type, items in iocs.items():
                            st.caption(ioc_type.upper())
                            st.code("\n".join(items), language="text")
                    else:
                        st.caption("None in the feed text. Check the original article.")
                with right:
                    st.markdown("<div class='pb-head'>Recommended response</div>", unsafe_allow_html=True)
                    blocks = [
                        f"<div class='pb'><div class='section-sub'>{esc(t)}</div><ol>"
                        + "".join(f"<li>{esc(s)}</li>" for s in rs.THREAT_MATRIX[t]["playbook"]) + "</ol></div>"
                        for t in row["tags"] if t in rs.THREAT_MATRIX
                    ]
                    st.markdown("".join(blocks) or "<div class='section-sub'>No playbook for this item.</div>",
                                unsafe_allow_html=True)


with tab_feed:
    if fdf.empty:
        st.info("No items match the current filters.", icon=":material/filter_alt_off:")
    else:
        t1, t2, t3, t4 = st.columns([2.4, 1.3, 1, 1], vertical_alignment="bottom")
        sort = t2.selectbox("Sort by", ["Most recent", "Highest severity"])
        pages = max((len(fdf) - 1) // PAGE_SIZE + 1, 1)
        ss.f_page = min(ss.f_page, pages)
        page = t3.number_input(f"Page of {pages}", min_value=1, max_value=pages, key="f_page")
        export = fdf[["published_at", "severity", "source", "title", "url", "threat_tags", "summary"]]
        t4.download_button("Export", export.to_csv(index=False).encode(), icon=":material/download:",
                           file_name=f"threat_intel_{now:%Y-%m-%d}.csv", mime="text/csv", width="stretch")
        view = fdf if sort == "Most recent" else fdf.sort_values(["severity", "published"], ascending=[True, False])
        first = (page - 1) * PAGE_SIZE
        t1.markdown(f"<div class='section-sub'>Showing {first + 1}–{min(first + PAGE_SIZE, len(fdf))} "
                    f"of {len(fdf):,} items</div>", unsafe_allow_html=True)
        for _, row in view.iloc[first:first + PAGE_SIZE].iterrows():
            render_row(row)

# ==========================================
# 8. ANALYTICS
# ==========================================
def style_chart(chart, height=260):
    return (chart.properties(height=height, background="transparent")
            .configure(font="Inter, system-ui, sans-serif")
            .configure_axis(labelColor=MUTED, titleColor=MUTED, gridColor=HAIRLINE,
                            domainColor=BASELINE, tickColor=BASELINE, labelFontSize=11)
            .configure_view(stroke=None)
            .configure_legend(labelColor=INK_2, titleColor=MUTED, orient="top", symbolType="circle"))


def bar_ranking(data: pd.DataFrame, field: str, title: str):
    base_chart = alt.Chart(data).encode(
        y=alt.Y(f"{field}:N", sort="-x", title=None, axis=alt.Axis(labelLimit=200)),
        x=alt.X("count:Q", title=None, axis=alt.Axis(tickMinStep=1)),
        tooltip=[alt.Tooltip(f"{field}:N", title=title), alt.Tooltip("count:Q", title="Articles")],
    )
    bars = base_chart.mark_bar(color=ACCENT, cornerRadiusEnd=3, height={"band": 0.65})
    values = base_chart.mark_text(align="left", dx=5, color=INK_2, fontSize=11).encode(text="count:Q")
    return style_chart(bars + values, height=max(26 * len(data), 120))


def panel_heading(title: str, sub: str):
    st.markdown(f"<div class='section-title'>{title}</div><div class='section-sub'>{sub}</div>",
                unsafe_allow_html=True)


with tab_analytics:
    if fdf.empty:
        st.info("No items match the current filters.", icon=":material/filter_alt_off:")
    else:
        with st.container(key="panel_daily"):
            panel_heading("Daily volume", "Articles per day, stacked by severity")
            daily = (fdf.assign(day=fdf["published"].dt.strftime("%Y-%m-%d"))
                     .groupby(["day", "severity"], observed=True).size().reset_index(name="count"))
            chart = alt.Chart(daily).mark_bar(stroke=SURFACE, strokeWidth=1.5).encode(
                x=alt.X("yearmonthdate(day):T", title=None,
                        axis=alt.Axis(format="%d %b", labelAngle=0, tickCount={"interval": "day", "step": 1},
                                      labelOverlap=True, grid=False)),
                y=alt.Y("count:Q", title=None, stack="zero", axis=alt.Axis(tickMinStep=1)),
                color=alt.Color("severity:N", title=None,
                                scale=alt.Scale(domain=list(SEVERITY_COLORS), range=list(SEVERITY_COLORS.values()))),
                order=alt.Order("sev_rank:Q"),
                tooltip=[alt.Tooltip("yearmonthdate(day):T", title="Day", format="%a %d %b"),
                         alt.Tooltip("severity:N", title="Severity"), alt.Tooltip("count:Q", title="Articles")],
            ).transform_calculate(sev_rank="indexof(['Critical','High','Medium','Low'], datum.severity)")
            st.altair_chart(style_chart(chart), width="stretch", theme=None)

        left, right = st.columns(2, gap="medium")
        with left, st.container(key="panel_cats"):
            panel_heading("Threat categories", "Articles per category (an article can have several)")
            cats = fdf.explode("tags").dropna(subset=["tags"]).groupby("tags").size().reset_index(name="count")
            if cats.empty:
                st.caption("No categorised articles in this selection.")
            else:
                st.altair_chart(bar_ranking(cats, "tags", "Category"), width="stretch", theme=None)
        with right, st.container(key="panel_sources"):
            panel_heading("Top sources", "The 12 sources with most articles in this selection")
            srcs = fdf.groupby("source").size().reset_index(name="count").nlargest(12, "count")
            st.altair_chart(bar_ranking(srcs, "source", "Source"), width="stretch", theme=None)

        with st.container(key="panel_cves"):
            panel_heading("Vulnerabilities in the news", "CVEs ranked by number of articles mentioning them")
            cve_rows = fdf.explode("cves").dropna(subset=["cves"])
            if cve_rows.empty:
                st.caption("No CVEs mentioned in this selection.")
            else:
                cve_table = (cve_rows.groupby("cves")
                             .agg(mentions=("id", "count"), sources=("source", lambda s: ", ".join(sorted(set(s)))),
                                  first_seen=("published", "min"), worst=("severity", "min"))
                             .reset_index().rename(columns={"cves": "cve"})
                             .sort_values(["mentions", "first_seen"], ascending=[False, False]))
                cve_table["nvd"] = "https://nvd.nist.gov/vuln/detail/" + cve_table["cve"]
                st.dataframe(
                    cve_table[["cve", "mentions", "worst", "first_seen", "sources", "nvd"]],
                    hide_index=True, width="stretch",
                    column_config={
                        "cve": "CVE", "mentions": st.column_config.NumberColumn("Mentions", width="small"),
                        "worst": "Highest severity",
                        "first_seen": st.column_config.DatetimeColumn("First seen", format="D MMM YYYY"),
                        "sources": "Reported by",
                        "nvd": st.column_config.LinkColumn("NVD", display_text="View"),
                    },
                )

# ==========================================
# 9. INDICATORS
# ==========================================
with tab_iocs:
    records = [
        {"type": t.upper(), "value": v, "severity": r["severity"], "article": r["title"],
         "source": r["source"], "published": r["published"], "url": r["url"]}
        for _, r in fdf.iterrows() for t, vals in r["ioc_dict"].items() for v in vals
    ]
    if not records:
        st.info("No indicators in the current selection. Widen the time window or reset the filters.",
                icon=":material/info:")
    else:
        ioc_df = pd.DataFrame(records)
        i1, i2, i3 = st.columns([3, 1, 1], vertical_alignment="bottom")
        with i1:
            types = st.pills("Indicator type", sorted(ioc_df["type"].unique()), selection_mode="multi")
        if types:
            ioc_df = ioc_df[ioc_df["type"].isin(types)]
        blocklist = ioc_df[ioc_df["type"].isin(["IPV4", "SHA256", "SHA1", "MD5"])]
        i2.download_button("CSV", ioc_df.to_csv(index=False).encode(), icon=":material/download:",
                           file_name=f"indicators_{now:%Y-%m-%d}.csv", mime="text/csv", width="stretch")
        i3.download_button("Blocklist", "\n".join(sorted(set(blocklist["value"]))).encode(),
                           icon=":material/block:", file_name=f"blocklist_{now:%Y-%m-%d}.txt", mime="text/plain",
                           width="stretch", disabled=blocklist.empty,
                           help="Unique IPs and hashes, one per line, for EDR / firewall import.")
        st.dataframe(
            ioc_df, hide_index=True, width="stretch", height=480,
            column_config={
                "type": st.column_config.TextColumn("Type", width="small"),
                "value": st.column_config.TextColumn("Indicator", width="large"),
                "severity": "Severity", "article": "Article", "source": "Source",
                "published": st.column_config.DatetimeColumn("Published", format="D MMM YYYY"),
                "url": st.column_config.LinkColumn("Link", display_text="Open"),
            },
        )
