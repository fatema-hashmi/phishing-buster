# 🛡️ Phishing Buster

A **Streamlit app** that helps spot common signs of phishing emails.🚀

---

## 🔍 What it checks
- ⚠️ **Urgency words / suspicious phrases** (e.g., “urgent”, “verify your account”, “account suspended”)  
- 🌐 **Links** with red flags:
  - Raw IP addresses
  - Punycode (look-alike domains)
  - Risky TLDs (like `.xyz`, `.top`, `.zip`)
  - Non-HTTPS (`http://`)
  - Extra-long URLs
- 📩 **Upload `.eml` files**:
  - Shows headers (From, Subject, Date)
  - Flags risky attachment types
  - Simple brand vs. link domain mismatch

---

## 🖥️ How to run

### On Windows
```bat
python -m venv .venv
.\.venv\Scripts\activate
pip install -r requirements.txt
streamlit run app.py

Then open 👉 http://localhost:8501

On Mac / Linux
python3 -m venv .venv
source ./.venv/bin/activate
pip install -r requirements.txt
streamlit run app.py
