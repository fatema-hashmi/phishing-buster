# Phishing Buster

Simple Streamlit app that checks emails for common phishing signs.

## What it checks
- Words/phrases that scammers use (e.g., “urgent”, “verify your account”, “account suspended”)
- Link red flags: raw IP domains, punycode (look-alike domains), risky TLDs, http (not https), very long URLs
- Upload `.eml` files (shows headers/attachments). Flags risky attachment types and brand/name mismatch.

## How to run (Windows)
```bat
python -m venv .venv
.\.venv\Scripts\activate
pip install -r requirements.txt
streamlit run app.py



Then open http://localhost:8501


How to run (Mac/Linux):
python3 -m venv .venv
source ./.venv/bin/activate
pip install -r requirements.txt
streamlit run app.py

