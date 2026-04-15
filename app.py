import streamlit as st
from analyzer.parser import parse_headers
from analyzer.spf import analyze_spf
from analyzer.dkim import analyze_dkim
from analyzer.dmarc import analyze_dmarc
from analyzer.risk import calculate_risk

st.set_page_config(page_title="Email Header Analyzer", layout="wide")

st.title("📧 Email Header Security Analyzer")

raw_headers = st.text_area("Paste Raw Email Headers", height=300)

if st.button("Analyze"):
    if len(raw_headers) > 1000000:
        st.error("Header too large!")
    else:
        parsed = parse_headers(raw_headers)

        spf = analyze_spf(parsed)
        dkim = analyze_dkim(parsed)
        dmarc = analyze_dmarc(parsed)

        risk_score, verdict = calculate_risk(spf, dkim, dmarc, parsed)

        st.subheader("🔍 Summary")
        st.metric("Risk Score", risk_score)

        if verdict == "Safe":
            st.success("✅ Safe Email")
        elif verdict == "Suspicious":
            st.warning("⚠️ Suspicious Email")
        else:
            st.error("🚨 Malicious Email")

        col1, col2, col3 = st.columns(3)

        with col1:
            st.info(f"SPF: {spf['result']}")

        with col2:
            st.info(f"DKIM: {dkim['result']}")

        with col3:
            st.info(f"DMARC: {dmarc['result']}")

        st.subheader("📊 Detailed Analysis")
        st.json({
            "Parsed Headers": parsed,
            "SPF": spf,
            "DKIM": dkim,
            "DMARC": dmarc
        })