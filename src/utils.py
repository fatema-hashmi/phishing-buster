# src/utils.py

URGENCY_WORDS = [
    "urgent","verify","password","login","invoice","overdue",
    "suspend","immediately","now","action required","confirm","security alert"
]

def find_urgency(text: str):
    if not text:
        return []
    t = text.lower()
    return [w for w in URGENCY_WORDS if w in t]

def score_email_mvp(body: str):
    """
    MVP scoring: only urgency words.
    returns (score:int, reasons:list[str])
    """
    reasons = []
    score = 0
    hits = find_urgency(body)
    if hits:
        reasons.append(f"Urgency language: {', '.join(hits)}")
        score += 30
    return min(score, 100), reasons


# ------------------------------
# Sprint 2: link checks + extras
# ------------------------------
import re
from urllib.parse import urlparse

# src/utils.py  — very simple, readable rules

# 1) words that often show up in fake emails
URGENCY_WORDS = [
    "urgent", "verify", "password", "login", "invoice", "overdue",
    "suspend", "immediately", "now", "action required", "confirm", "security alert"
]

EXTRA_PHRASES = [
    "verify your account", "confirm your account", "unusual activity",
    "account locked", "account suspended", "update payment",
    "tax refund", "delivery issue", "gift card", "reset your account"
]

# 2) TLDs (endings) that show up a lot in phishy links
RISKY_TLDS = {
    "zip","top","xyz","click","work","gq","tk","ml","cf","pw",
    "link","quest","cam","fit","review","party","download","loan",
    "club","kim","mom"
}


# ---------------------------
# helpers (all very simple)
# ---------------------------
def find_urgency(text):
    """Return urgency words found in the text (simple contains)."""
    hits = []
    if not text:
        return hits
    t = text.lower()
    for w in URGENCY_WORDS:
        if w in t:
            hits.append(w)
    return hits


def find_extra_phrases(text):
    """Return extra suspicious phrases found in the text."""
    hits = []
    if not text:
        return hits
    t = text.lower()
    for p in EXTRA_PHRASES:
        if p in t:
            hits.append(p)
    return hits


def get_links(text):
    """
    SUPER simple link finder:
    split on spaces and keep tokens that start with http:// or https://
    then remove trailing punctuation.
    """
    if not text:
        return []
    tokens = text.split()
    links = []
    for tok in tokens:
        if tok.startswith("http://") or tok.startswith("https://"):
            # strip a few common trailing chars
            while len(tok) > 0 and tok[-1] in ").,;:'\">":
                tok = tok[:-1]
            if tok not in links:
                links.append(tok)
    return links


def get_domain(link):
    """Take 'https://example.com/path' -> 'example.com' (lowercased)."""
    if not link:
        return ""
    s = link
    if "://" in s:
        s = s.split("://", 1)[1]
    # domain is before the first slash
    if "/" in s:
        s = s.split("/", 1)[0]
    return s.lower()


def is_ip(domain):
    """
    Very basic IPv4 check: four numbers 0-255 separated by dots.
    (Good enough for this demo.)
    """
    parts = domain.split(".")
    if len(parts) != 4:
        return False
    for p in parts:
        if not p.isdigit():
            return False
        n = int(p)
        if n < 0 or n > 255:
            return False
    return True


def uses_punycode(domain):
    """Look-alike domains often use 'xn--'."""
    return "xn--" in (domain or "")


def has_risky_tld(domain):
    """Check the last dot-part of the domain."""
    if not domain or "." not in domain:
        return False
    tld = domain.split(".")[-1]
    return tld in RISKY_TLDS


def is_http_not_https(link):
    return link.lower().startswith("http://")


def is_very_long(link, threshold=110):
    return len(link) >= threshold


# -------------------------------------------
# main scorer used by app.py (keep this name)
# -------------------------------------------
def score_with_urls(text):
    """
    Build a simple score and reasons list.
    Nothing fancy: plain loops + ifs.
    Returns (score, reasons, links)
    """
    score = 0
    reasons = []

    # 1) text signals
    urg = find_urgency(text)
    if len(urg) > 0:
        reasons.append("Urgency language: " + ", ".join(urg))
        score = score + 15

    extra = find_extra_phrases(text)
    if len(extra) > 0:
        reasons.append("Suspicious phrases: " + ", ".join(extra))
        score = score + 15

    # 2) links
    links = get_links(text)
    if len(links) >= 4:
        score = score + 5  # lots of links can be sketchy

    for link in links:
        domain = get_domain(link)
        flags = []

        if is_ip(domain):
            flags.append("uses raw IP")
            score = score + 25

        if uses_punycode(domain):
            flags.append("punycode (look-alike risk)")
            score = score + 25

        if has_risky_tld(domain):
            flags.append("risky TLD")
            score = score + 15

        if is_http_not_https(link):
            flags.append("not HTTPS")
            score = score + 10

        if is_very_long(link):
            flags.append("very long URL")
            score = score + 8

        if len(flags) > 0:
            reasons.append(link + " → " + ", ".join(flags))

    # cap score
    if score > 100:
        score = 100

    return score, reasons, links



# -------------------------------------------
# simple .eml support (beginner-friendly)
# -------------------------------------------
from email import policy
from email.parser import BytesParser

# small list of attachment types that are often risky
RISKY_ATTACH = [".html", ".htm", ".exe", ".scr", ".bat", ".cmd", ".js", ".vbs", ".zip", ".rar", ".7z", ".iso", ".img"]

# a few common brands phishers impersonate (change as you like)
COMMON_BRANDS = ["microsoft", "google", "outlook", "gmail", "apple", "amazon",
                 "paypal", "anz", "asb", "westpac", "xero", "dhl", "nz post"]

def parse_eml_bytes(b):
    """
    Return (headers_dict, body_text, attachment_names)
    We only read plain text parts to keep it simple.
    """
    msg = BytesParser(policy=policy.default).parsebytes(b)

    headers = {
        "from": str(msg.get("From", "")),
        "to": str(msg.get("To", "")),
        "subject": str(msg.get("Subject", "")),
        "date": str(msg.get("Date", "")),
    }

    body_parts = []
    attachments = []

    if msg.is_multipart():
        for part in msg.walk():
            # collect attachment names (if any)
            fn = part.get_filename()
            if fn:
                attachments.append(fn)

            # collect plain text
            if part.get_content_type() == "text/plain":
                try:
                    body_parts.append(part.get_content())
                except Exception:
                    try:
                        body_parts.append(part.get_payload(decode=True).decode("utf-8", "ignore"))
                    except Exception:
                        pass
    else:
        # non-multipart: try text directly
        try:
            body_parts.append(msg.get_content())
        except Exception:
            try:
                body_parts.append(msg.get_payload(decode=True).decode("utf-8", "ignore"))
            except Exception:
                pass

    body = "\n".join([p for p in body_parts if p])
    return headers, body, attachments


def find_risky_attachments(names):
    """Return a list of filenames with risky extensions."""
    risky = []
    for fn in names or []:
        dot = fn.rfind(".")
        ext = fn[dot:].lower() if dot != -1 else ""
        if ext in RISKY_ATTACH:
            risky.append(fn)
    return risky


def simple_brand_mismatch(text, links):
    """
    If the email mentions a brand but none of the link domains contain that brand,
    add a note. (Very rough, but shows your thinking.)
    """
    t = (text or "").lower()
    if not links:
        return []

    # gather all link domains into one string
    domains_text = " ".join(get_domain(u) for u in links)

    mismatches = []
    for brand in COMMON_BRANDS:
        if brand in t:
            token = brand.replace(" ", "")
            if token not in domains_text:
                mismatches.append(brand)
    return mismatches
