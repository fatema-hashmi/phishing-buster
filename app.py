import streamlit as st
from src.utils import score_with_urls, parse_eml_bytes, find_risky_attachments, simple_brand_mismatch

st.set_page_config(page_title="Phishing Buster", page_icon="🛡️", layout="centered")
st.title("🛡️ Phishing Buster")
st.caption("Paste email text or upload a .eml file. Simple rules, clear reasons.")

tab_text, tab_eml = st.tabs(["Paste text", "Upload .eml"])

with tab_text:
    body = st.text_area("Paste the email (include any links).", height=220, placeholder="Paste here...")
    if st.button("Analyze (text)", key="analyze_text"):
        score, reasons, links = score_with_urls(body)

        st.metric("Risk score", f"{score}/100")
        if score >= 60:
            st.error("High risk — looks phishy.")
        elif score >= 30:
            st.warning("Medium risk — be careful.")
        else:
            st.success("Low risk — still review carefully.")

        st.write("**Why?**")
        if reasons:
            for r in reasons:
                st.write("• " + r)
        else:
            st.write("No strong indicators found.")

        st.write("**Links found**")
        if links:
            for u in links:
                st.code(u)
        else:
            st.write("No links detected.")

with tab_eml:
    up = st.file_uploader("Choose a .eml file", type=["eml"])
    if up is not None:
        headers, body, attach = parse_eml_bytes(up.read())

        st.subheader("Email headers")
        st.write("**From:**", headers.get("from", ""))
        st.write("**To:**", headers.get("to", ""))
        st.write("**Subject:**", headers.get("subject", ""))
        st.write("**Date:**", headers.get("date", ""))

        st.write("**Attachments:**", ", ".join(attach) if attach else "None")

        if st.button("Analyze (.eml)", key="analyze_eml"):
            score, reasons, links = score_with_urls(body)

            # add simple attachment + brand notes (no scoring change unless you want it)
            risky = find_risky_attachments(attach)
            if risky:
                reasons.append("Risky attachment(s): " + ", ".join(risky))
                score = min(100, score + 20)  # small bonus score for risk

            mm = simple_brand_mismatch(body, links)
            if mm:
                reasons.append("Brand mentioned but not in link domains: " + ", ".join(mm))
                score = min(100, score + 15)

            st.metric("Risk score", f"{score}/100")
            if score >= 60:
                st.error("High risk — this looks phishy.")
            elif score >= 30:
                st.warning("Medium risk — be careful.")
            else:
                st.success("Low risk — still review carefully.")

            st.write("**Why?**")
            if reasons:
                for r in reasons:
                    st.write("• " + r)
            else:
                st.write("No strong indicators found.")

            st.write("**Links found**")
            if links:
                for u in links:
                    st.code(u)
            else:
                st.write("No links detected.")

            with st.expander("Raw body (first 5,000 chars)"):
                st.text((body or "")[:5000])

