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

    # Input validation
    if not raw_headers.strip():
        st.error("Please paste email headers first.")

    elif len(raw_headers) > 1000000:
        st.error("Header too large!")

    elif "Received:" not in raw_headers:
        st.error("❌ Invalid email headers. Please paste proper raw headers.")

    else:
        # Parse headers
        parsed = parse_headers(raw_headers)

        # Authentication checks
        spf = analyze_spf(parsed)
        dkim = analyze_dkim(parsed)
        dmarc = analyze_dmarc(parsed)

        # Risk calculation
        risk_score, verdict = calculate_risk(spf, dkim, dmarc, parsed)

        # Human explanation
        explanation = generate_explanation(
            parsed,
            spf,
            dkim,
            dmarc,
            risk_score,
            verdict
        )

        # Summary
        st.subheader("🔍 Security Summary")
        st.metric("Risk Score", risk_score)

        if verdict == "Safe":
            st.success("✅ SAFE EMAIL")
            st.write(
                "This email appears legitimate because the authentication checks passed and no major suspicious indicators were detected."
            )
        elif verdict == "Suspicious":
            st.warning("⚠️ SUSPICIOUS EMAIL")
            st.write(
                "This email has some warning signs. It may be legitimate, but it should be verified carefully before taking action."
            )
        else:
            st.error("🚨 MALICIOUS EMAIL")
            st.write(
                "This email appears risky and may be part of a phishing or spoofing attempt."
            )

        # Authentication results
        st.subheader("📌 Authentication Results")

        col1, col2, col3 = st.columns(3)

        with col1:
            if spf["result"] == "pass":
                st.success(f"SPF: {spf['result']}")
            else:
                st.error(f"SPF: {spf['result']}")

        with col2:
            if dkim["result"] == "pass":
                st.success(f"DKIM: {dkim['result']}")
            else:
                st.error(f"DKIM: {dkim['result']}")

        with col3:
            if dmarc["result"] == "pass":
                st.success(f"DMARC: {dmarc['result']}")
            else:
                st.error(f"DMARC: {dmarc['result']}")

        # Simple explanation
        st.subheader("🧠 Explanation")

        st.write(f"**Verdict:** {explanation['verdict']}")
        st.write(f"**Risk Score:** {explanation['risk_score']} / 100")

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

        # Optional raw data hidden inside an expander
        with st.expander("Show technical details"):
            st.write(parsed)