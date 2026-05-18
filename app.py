import streamlit as st
from analyzer.parser import parse_headers
from analyzer.spf import analyze_spf
from analyzer.dkim import analyze_dkim
from analyzer.dmarc import analyze_dmarc
from analyzer.risk import calculate_risk
from analyzer.explainer import generate_explanation

st.set_page_config(page_title="Email Header Analyzer", layout="wide")

st.title("📧 Email Header Security Analyzer")

raw_headers = st.text_area("Paste Raw Email Headers", height=300)

if st.button("Analyze"):
    if not raw_headers.strip():
        st.error("Please paste email headers first.")
    elif len(raw_headers) > 1000000:
        st.error("Header too large!")
    elif "Received:" not in raw_headers and "Authentication-Results:" not in raw_headers:
        st.error("❌ Invalid email headers. Please paste proper raw headers.")
    else:
        parsed = parse_headers(raw_headers)
        spf = analyze_spf(parsed)
        dkim = analyze_dkim(parsed)
        dmarc = analyze_dmarc(parsed)

        risk_score, verdict, risk_reasons = calculate_risk(spf, dkim, dmarc, parsed)

        explanation = generate_explanation(
            parsed,
            spf,
            dkim,
            dmarc,
            risk_score,
            verdict,
            risk_reasons
        )

        st.subheader("🔍 Security Summary")
        st.metric("Risk Score", risk_score)

        if verdict == "Safe":
            st.success("✅ SAFE EMAIL")
        elif verdict == "Suspicious":
            st.warning("⚠️ SUSPICIOUS EMAIL")
        else:
            st.error("🚨 MALICIOUS EMAIL")

        st.subheader("🧠 Simple Explanation")
        st.write(explanation["summary"])

        st.subheader("❌ Why it may be dangerous")
        if explanation["why_suspicious"]:
            for reason in explanation["why_suspicious"]:
                st.error(f"• {reason}")
        else:
            st.success("No major suspicious indicators detected.")

        st.subheader("✅ Why it may be legitimate")
        if explanation["why_safe"]:
            for good in explanation["why_safe"]:
                st.success(f"• {good}")
        else:
            st.info("No positive indicators found.")