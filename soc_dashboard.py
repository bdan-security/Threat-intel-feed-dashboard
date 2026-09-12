import streamlit as st
import pandas as pd
import sqlite3
import json
import os

# ==========================================
# 1. PAGE CONFIGURATION
# ==========================================
st.set_page_config(page_title="SOC Defense Intel", page_icon="🛡️", layout="wide")

st.title("🛡️ Internal SOC Defense Dashboard")
st.markdown("Automated Threat Extraction, IoCs, and Response Playbooks.")

# ==========================================
# 2. LOAD DATA FROM DATABASE
# ==========================================
db_path = 'company_defense.db'

if not os.path.exists(db_path):
    st.warning("⚠️ Database not found! Please run `python intel_ingestor.py` first.")
    st.stop()

conn = sqlite3.connect(db_path)
df = pd.read_sql_query("SELECT * FROM intel ORDER BY id DESC", conn)
conn.close()

if df.empty:
    st.info("No threat intel found in the database yet.")
    st.stop()

# ==========================================
# 3. SIDEBAR FILTERS
# ==========================================
st.sidebar.header("🔍 Filter Intel")

search_query = st.sidebar.text_input("Search Text or IoCs...")

# Extract unique threat tags for clean sidebar selection
all_tags = set(x.strip() for sublist in df['threat_tags'].dropna() for x in sublist.split(',') if x)
selected_tags = st.sidebar.multiselect("Filter by Threat Type", list(all_tags))

# Apply filters to working dataset
filtered_df = df.copy()

if search_query:
    filtered_df = filtered_df[
        filtered_df['title'].str.contains(search_query, case=False, na=False) |
        filtered_df['summary'].str.contains(search_query, case=False, na=False) |
        filtered_df['iocs'].str.contains(search_query, case=False, na=False)
    ]

if selected_tags:
    pattern = '|'.join(selected_tags)
    filtered_df = filtered_df[filtered_df['threat_tags'].str.contains(pattern, case=False, na=False)]

st.sidebar.divider()
st.sidebar.metric("Alerts Displayed", len(filtered_df))

# ==========================================
# 4. DASHBOARD UI LAYOUT
# ==========================================
st.divider()

# --- THE FIX: Limit rows rendered to prevent browser lag ---
DISPLAY_LIMIT = 20
total_results = len(filtered_df)

if total_results > DISPLAY_LIMIT:
    st.info(f"⚠️ **Performance Limit:** Showing the top {DISPLAY_LIMIT} results out of {total_results}. Use the sidebar filters to narrow down your search.")
    working_df = filtered_df.head(DISPLAY_LIMIT)
else:
    working_df = filtered_df

if working_df.empty:
    st.warning("No alerts match your current filters.")
else:
    for index, row in working_df.iterrows():
        # Article Header
        st.subheader(f"🚨 {row['title']}")
        
        # Displaying Source alongside the Date
        st.caption(f"**Source:** {row['source']} | **Published:** {row.get('date', 'Unknown Date')} | **[🔗 View Original Source]({row['url']})**")
        
        # Display Threat Tags
        if row['threat_tags']:
            tags = row['threat_tags'].split(',')
            formatted_tags = " ".join([f"`{tag.strip()}`" for tag in tags if tag])
            st.markdown(f"**Detected Threats:** {formatted_tags}")

        # Summary Window
        st.write(row['summary'])

        # Layout Allocation columns
        col1, col2 = st.columns([1, 1.5])
        
        with col1:
            st.markdown("### 🔬 Indicators of Compromise (IoCs)")
            try:
                iocs = json.loads(row['iocs']) 
                if iocs:
                    for ioc_type, items in iocs.items():
                        st.markdown(f"**{ioc_type.upper()}**")
                        for item in items:
                            st.code(item, language="text")
                else:
                    st.info("No technical indicators extracted.")
            except Exception:
                st.error("Error parsing IoCs.")

        with col2:
            st.markdown("### 📋 Automated Playbooks")
            if row['playbooks']:
                st.info(row['playbooks'])
            else:
                st.success("No critical threat keywords detected. Routine monitoring advised.")
        
        st.divider()
