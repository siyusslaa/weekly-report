import os
import re
import pdfplumber
import pandas as pd
import pycountry
from collections import OrderedDict, Counter
from typing import List, Tuple, Dict, Set, Optional

# =========================================
# 1. Dataset Driven Country Mapping
# =========================================

def build_country_database():
    mapping: Dict[str, str] = {
        "US": "United States",
        "USA": "United States",
        "U.S.": "United States",
        "UK": "United Kingdom",
        "U.K.": "United Kingdom",
        "UAE": "United Arab Emirates",
        "KSA": "Saudi Arabia",
        "MY": "Malaysia",
    }

    demonyms = {
        "Mexican": "Mexico",
        "Brazilian": "Brazil",
        "German": "Germany",
        "Colombian": "Colombia",
        "Thai": "Thailand",
        "Malaysian": "Malaysia",
        "Indonesian": "Indonesia",
        "Irish": "Ireland",
        "Spanish": "Spain",
        "Portuguese": "Portugal",
        "South African": "South Africa",
        "Moroccan": "Morocco",
        "Chinese": "China",
        "Indian": "India",
        "South Korean": "South Korea",
        "American": "United States",
        "British": "United Kingdom",
        "Vietnamese": "Vietnam",
        "Russian": "Russian Federation",
        "French": "France",
        "Israeli": "Israel",
        "Israelis": "Israel",
        "Romanian": "Romania",
        "Canadian": "Canada",
        "Venezuela":"Venezuela"
    }

    for key, val in demonyms.items():
        mapping[key] = val

    for c in pycountry.countries:
        mapping[c.name] = c.name

    return mapping


COUNTRY_MAP = build_country_database()

SECTION_HEADERS = ["ACCESS", "DATA", "MALWARE", "OTHER", "VULNERABILITY"]
IGNORE_WORDS = {
    "THREAT", "DETAIL", "ACTIVITY", "ALERTS",
    "RELAY", "SOURCE", "PAGE", "VERSION", "PUBLISH"
}

# =========================================
# 2. Helper Functions
# =========================================

def extract_countries(text: str) -> Set[str]:
    found: Set[str] = set()
    for key, formal in COUNTRY_MAP.items():
        if re.search(r"\b" + re.escape(key) + r"\b", text, re.I):
            found.add(formal)
    return found


def is_bold(word: Dict) -> bool:
    font = word.get("fontname", "").lower()
    return "bold" in font or "black" in font or "heavy" in font


def clean_description(desc: str) -> str:
    sources = [
        "DarkForums", "Exploit", "RAMP", "Leakbase",
        "Telegram", "Breachforums", "XSS", "Hackforums", "Deepwebchinese"
    ]

    for src in sources:
        desc = re.sub(rf"\b{re.escape(src)}\b", "", desc, flags=re.I)

    desc = re.sub(r"\s+", " ", desc).strip()
    if desc and not desc.endswith((".", "!", "?")):
        desc += "."
    return desc


def save_incident(store, category, actor_parts, desc_words):
    if not actor_parts:
        return

    actor = " ".join(actor_parts).strip()
    desc = " ".join(desc_words).replace(" .", ".").strip()
    desc = re.sub(r"^[\d\s\.\•\-]+", "", desc)
    desc = clean_description(desc)

    if actor and desc:
        store[category].append({
            "actor": actor,
            "desc": desc
        })


# =========================================
# 3. Word Stream PDF Parsing
# =========================================

def get_word_stream_incidents(pdf_path: str):
    data = {k.capitalize(): [] for k in ["Access", "Data", "Malware", "Other"]}
    current_category = "Other"
    current_actor_parts: List[str] = []
    current_desc_words: List[str] = []

    with pdfplumber.open(pdf_path) as pdf:
        words = []
        for page in pdf.pages:
            page_words = page.extract_words(extra_attrs=["fontname"])
            words.extend(page_words)

    start_idx = 0
    for i, w in enumerate(words):
        if w["text"].upper() == "THREAT" and i + 1 < len(words) and words[i + 1]["text"].upper() == "DETAIL":
            start_idx = i + 2
            break

    for i in range(start_idx, len(words)):
        w = words[i]
        txt = w["text"]
        upper = txt.upper()

        if upper == "THREAT" and i + 1 < len(words) and words[i + 1]["text"].upper() == "ACTIVITY":
            break

        if is_bold(w) and upper in SECTION_HEADERS:
            if current_actor_parts:
                save_incident(data, current_category, current_actor_parts, current_desc_words)
            current_category = "Other" if upper == "VULNERABILITY" else upper.capitalize()
            current_actor_parts, current_desc_words = [], []
            continue

        if is_bold(w) and upper not in IGNORE_WORDS and not txt.isdigit():
            if current_desc_words:
                save_incident(data, current_category, current_actor_parts, current_desc_words)
                current_actor_parts, current_desc_words = [txt], []
            else:
                current_actor_parts.append(txt)
        else:
            if current_actor_parts and txt not in {"•", "–"}:
                current_desc_words.append(txt)

    if current_actor_parts:
        save_incident(data, current_category, current_actor_parts, current_desc_words)

    return data


# =========================================
# 4. Aggregation and Analytics
# =========================================

def count_incidents_from_df(df: pd.DataFrame) -> int:
    if "Incident" not in df.columns:
        return 0

    total = 0
    for val in df["Incident"]:
        if not isinstance(val, str):
            continue
        total += val.count("•") if "•" in val else 1
    return total


def build_all_tables_from_pdfs(pdf_paths: List[str]):
    storage = {
        cat: {"inc": OrderedDict(), "cty": []}
        for cat in ["Access", "Data", "Malware", "Other"]
    }

    for path in sorted(pdf_paths):
        parsed = get_word_stream_incidents(path)
        for cat, items in parsed.items():
            for itm in items:
                act, dsc = itm["actor"], itm["desc"]
                if act not in storage[cat]["inc"]:
                    storage[cat]["inc"][act] = []
                storage[cat]["inc"][act].append(dsc)
                storage[cat]["cty"].append((cat, dsc))

    def build_df(cat: str, include_country: bool = False) -> pd.DataFrame:
        rows = []
        for idx, (actor, descs) in enumerate(storage[cat]["inc"].items(), 1):
            text = "\n".join(f"• {d}" for d in descs) if len(descs) > 1 else descs[0]
            row = {
                "No.": idx,
                "Threat Actor": actor,
                "Incident": text,
            }
            if include_country:
                countries = set()
                for d in descs:
                    countries |= extract_countries(d)
                row["Country"] = ", ".join(sorted(countries)) or "Unknown"
            rows.append(row)
        return pd.DataFrame(rows)

    acc = build_df("Access", True)
    dat = build_df("Data", True)
    mal = build_df("Malware")
    oth = build_df("Other")

    access_cnt = count_incidents_from_df(acc)
    data_cnt = count_incidents_from_df(dat)
    malware_cnt = count_incidents_from_df(mal)
    other_cnt = count_incidents_from_df(oth)

    tot = pd.DataFrame([
    {"Category": "Access Broker", "Count": access_cnt},
    {"Category": "Data Breaches", "Count": data_cnt},
    {"Category": "Malware", "Count": malware_cnt},
    {"Category": "Other Threats", "Count": other_cnt},
    {"Category": "Total", "Count": access_cnt + data_cnt + malware_cnt + other_cnt},
    ])

    country_counter: Counter = Counter()
    for cat in ["Access", "Data"]:
        for desc in [d for _, d in storage[cat]["cty"]]:
            for c in extract_countries(desc):
                country_counter[c] += 1

    cty = (
        pd.DataFrame(country_counter.items(), columns=["Country", "Occurrences"])
        .sort_values("Occurrences", ascending=False)
    )

    return acc, dat, mal, oth, tot, cty

