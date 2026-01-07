import os
import tempfile
from io import BytesIO

import streamlit as st
import pandas as pd
import plotly.express as px

from pdf_to_excel_access import build_all_tables_from_pdfs


# =========================================
# Helper functions
# =========================================

def count_incidents(df: pd.DataFrame) -> int:
    if "Incident" not in df.columns:
        return 0

    total = 0
    for val in df["Incident"]:
        if isinstance(val, str):
            total += val.count("•") if "•" in val else 1
    return total


def generate_dynamic_summary(counts: dict) -> str:
    total = sum(counts.values())

    if total == 0:
        return "No cyber security incidents were recorded during this reporting period."

    ranked = sorted(counts.items(), key=lambda x: x[1], reverse=True)
    parts = [f"{k} at {v} cases" for k, v in ranked if v > 0]

    if len(parts) == 1:
        return (
            f"A total of {total} cyber security incidents were recorded, "
            f"consisting solely of {parts[0]}."
        )

    return (
        f"A total of {total} cyber security incidents were recorded, "
        f"with {parts[0]} leading, followed by "
        + ", ".join(parts[1:-1])
        + f", while {parts[-1]}."
    )


def analyse_other_threats(oth_df: pd.DataFrame) -> str:
    if oth_df.empty or "Incident" not in oth_df.columns:
        return ""

    text = " ".join(oth_df["Incident"].dropna().astype(str)).lower()
    themes = []

    if any(k in text for k in ["phish", "phishing", "phishlet"]):
        themes.append("phishing operations")
    if any(k in text for k in ["credential", "cookie", "session", "account"]):
        themes.append("credential harvesting")
    if any(k in text for k in ["exploit", "zero-day", "cve", "rce", "lfi", "sqli"]):
        themes.append("vulnerability exploitation")
    if any(k in text for k in ["post compromise", "persistence", "lateral", "beacon", "c2"]):
        themes.append("post compromise access")

    if not themes:
        return (
            "Other Threats cases indicate the continued availability of varied offensive "
            "cyber tools within underground ecosystems."
        )

    themes = sorted(set(themes))

    if len(themes) == 1:
        sentence = f"Other Threats cases indicate activity focused on {themes[0]}."
    else:
        sentence = (
            "Other Threats cases indicate ongoing development and commercialisation "
            "of offensive cyber tools that support "
            + ", ".join(themes[:-1])
            + ", and "
            + themes[-1]
            + "."
        )

    if len(themes) >= 2:
        sentence += (
            " The observed activity reflects an organised underground market that "
            "prioritises scalability, operational efficiency, and rapid adoption of "
            "newly disclosed vulnerabilities."
        )

    return sentence


def build_excel_bytes(results):
    sheet_names = [
        "Access Broker",
        "Data Breaches",
        "Malware",
        "Other Threats",
        "Totals",
        "Country Occurrences",
    ]

    output = BytesIO()
    with pd.ExcelWriter(output, engine="xlsxwriter") as writer:
        for df, name in zip(results, sheet_names):
            df.to_excel(writer, index=False, sheet_name=name)
            worksheet = writer.sheets[name]
            for i, col in enumerate(df.columns):
                width = max(df[col].astype(str).map(len).max(), len(col)) + 2
                worksheet.set_column(i, i, min(width, 70))

    output.seek(0)
    return output


# =========================================
# Streamlit App
# =========================================

st.set_page_config(page_title="Weekly Report", layout="wide")


def main():
    st.title("🛡️ Mandiant Weekly Report Sorter")
    st.markdown(
        "Upload up to **5 Mandiant PDF reports** to generate an Excel report "
        "and incident dashboard."
    )

    uploaded_files = st.file_uploader(
        "Upload PDF reports (maximum 5 files)",
        type="pdf",
        accept_multiple_files=True,
    )

    status_placeholder = st.empty()
    progress_bar = st.progress(0)
    status_placeholder.text("Status: Idle")

    if not uploaded_files:
        st.info("No files uploaded yet.")
        return

    if st.button("Generate Master Excel & Dashboard"):
        progress_bar.progress(0)
        status_placeholder.text("Status: Preparing files")

        tmp_dir = tempfile.mkdtemp(prefix="taa_pdfs_")
        pdf_paths = []
        total_files = len(uploaded_files)

        for idx, f in enumerate(uploaded_files):
            status_placeholder.text(
                f"Status: Processing {f.name} ({idx + 1}/{total_files})"
            )
            path = os.path.join(tmp_dir, f.name)
            with open(path, "wb") as b:
                b.write(f.getbuffer())
            pdf_paths.append(path)
            progress_bar.progress((idx + 1) / total_files)

        status_placeholder.text("Status: Building analytics tables")

        try:
            acc, dat, mal, oth, tot, cty = build_all_tables_from_pdfs(pdf_paths)
        except Exception as e:
            status_placeholder.text("Status: Error")
            st.error(f"Processing failed: {e}")
            return

        access_cnt = count_incidents(acc)
        data_cnt = count_incidents(dat)
        malware_cnt = count_incidents(mal)
        other_cnt = count_incidents(oth)

        counts = {
            "Access Broker": access_cnt,
            "Data Breaches": data_cnt,
            "Malware": malware_cnt,
            "Other Threats": other_cnt,
        }

        status_placeholder.text("Status: Completed")
        progress_bar.progress(1.0)
        st.success("Analysis complete.")

        # =====================================
        # Executive Summary
        # =====================================

        st.divider()
        st.subheader("Executive Summary")

        st.markdown(generate_dynamic_summary(counts))

        other_summary = analyse_other_threats(oth)
        if other_summary:
            st.markdown(other_summary)

        # =====================================
        # Metrics
        # =====================================

        st.divider()
        m1, m2, m3, m4, m5 = st.columns(5)
        m1.metric("Access Broker", access_cnt)
        m2.metric("Data Breaches", data_cnt)
        m3.metric("Malware", malware_cnt)
        m4.metric("Other Threats", other_cnt)
        m5.metric("Total Incidents", sum(counts.values()))

        # =====================================
        # Charts
        # =====================================

        st.divider()
        st.subheader("Incident Overview")

        col1, col2 = st.columns(2)

        with col1:
            dist_df = pd.DataFrame({
                "Category": list(counts.keys()),
                "Incidents": list(counts.values()),
            })
            fig_pie = px.pie(
                dist_df,
                values="Incidents",
                names="Category",
                hole=0.4,
                title="Incident Distribution",
            )
            st.plotly_chart(fig_pie, use_container_width=True)

        with col2:
            if not cty.empty:
                top_cty = cty.head(10).sort_values("Occurrences", ascending=True)
                fig_bar = px.bar(
                    top_cty,
                    x="Occurrences",
                    y="Country",
                    orientation="h",
                    title="Top 10 Affected Countries",
                    color="Occurrences",
                    color_continuous_scale="Blues",
                )
                st.plotly_chart(fig_bar, use_container_width=True)
            else:
                st.info("No country data available.")

        # =====================================
        # Download
        # =====================================

        st.divider()
        excel_bytes = build_excel_bytes((acc, dat, mal, oth, tot, cty))
        st.download_button(
            "📥 Download Master Excel Report",
            excel_bytes,
            file_name="Weekly_Report.xlsx",
            mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        )


if __name__ == "__main__":
    main()
