import streamlit as st
import json
import re

from google import genai

from helpers import (
    validate_target,
    collect_intelligence
)


# ============================================================
# PAGE CONFIG
# ============================================================

st.set_page_config(
    page_title="ThreatLens",
    page_icon="🛡️",
    layout="wide"
)


# ============================================================
# CUSTOM CSS
# ============================================================

st.markdown(
    """
    <style>

    .main-title {
        font-size: 42px;
        font-weight: 700;
        margin-bottom: 5px;
    }

    .subtitle {
        font-size: 17px;
        color: #666666;
        margin-bottom: 25px;
    }

    .target-box {
        padding: 20px;
        border-radius: 12px;
        border: 1px solid #dddddd;
        margin-bottom: 20px;
    }

    .section-title {
        font-size: 22px;
        font-weight: 650;
        margin-top: 20px;
    }

    </style>
    """,
    unsafe_allow_html=True
)


# ============================================================
# HEADER
# ============================================================

st.markdown(
    '<div class="main-title">🛡️ ThreatLens</div>',
    unsafe_allow_html=True
)

st.markdown(
    '<div class="subtitle">'
    'Passive AI-powered threat intelligence analysis'
    '</div>',
    unsafe_allow_html=True
)


# ============================================================
# SIDEBAR
# ============================================================

with st.sidebar:

    st.header("⚙️ Settings")

    target_type = st.selectbox(
        "Target Type",
        [
            "IP",
            "Domain",
            "URL"
        ]
    )

    knowledge_level = st.selectbox(
        "Knowledge Level",
        [
            "Beginner",
            "Intermediate",
            "Expert"
        ]
    )

    st.divider()

    st.subheader("🔑 API Keys")

    otx_api_key = st.text_input(
        "AlienVault OTX API Key",
        type="password",
        help="Enter your AlienVault OTX API key."
    )

    gemini_api_key = st.text_input(
        "Gemini API Key",
        type="password",
        help="Enter your Google Gemini API key."
    )

    st.caption(
        "Keys are used only during the current session."
    )


# ============================================================
# TARGET INPUT
# ============================================================

st.subheader("🎯 Target")

if target_type == "IP":

    placeholder = "8.8.8.8"

elif target_type == "Domain":

    placeholder = "example.com"

else:

    placeholder = "https://example.com"


target = st.text_input(
    "Enter target",
    placeholder=placeholder
)


# ============================================================
# GEMINI ANALYSIS
# ============================================================

def analyze_with_gemini(
    target,
    target_type,
    knowledge_level,
    intelligence,
    api_key
):

    client = genai.Client(
        api_key=api_key
    )

    intelligence_json = json.dumps(
        intelligence,
        indent=2,
        ensure_ascii=False
    )

    prompt = f"""
You are ThreatLens AI, a cybersecurity
threat-intelligence assistant.

Analyze ONLY the evidence provided below.

Do not invent information.

TARGET:
{target}

TARGET TYPE:
{target_type}

USER KNOWLEDGE LEVEL:
{knowledge_level}

COLLECTED INTELLIGENCE:
{intelligence_json}

Determine whether the available evidence indicates:

SAFE
SUSPICIOUS
MALICIOUS
UNKNOWN

Return ONLY valid JSON.

Use exactly this structure:

{{
    "verdict": "UNKNOWN",
    "confidence": "LOW",
    "risk_score": 0,
    "summary": "Short simple explanation.",
    "evidence": [
        "Evidence point 1",
        "Evidence point 2"
    ],
    "risk": "Short explanation of the risk.",
    "recommended_action": "Short practical recommendation."
}}

Allowed verdict values:

SAFE
SUSPICIOUS
MALICIOUS
UNKNOWN

Allowed confidence values:

LOW
MEDIUM
HIGH

Risk score:

0-29 = Low Risk
30-69 = Medium Risk
70-100 = High Risk

Rules:

1. Never invent threat intelligence.
2. Never invent malware.
3. Never invent threat actors.
4. Never invent attacks.
5. Never invent CVEs.
6. Never invent locations.
7. Never invent organizations.
8. Never claim a target is malicious without evidence.
9. If evidence is insufficient, use UNKNOWN.
10. Keep explanations appropriate for the user's knowledge level.
11. risk_score must be an integer from 0 to 100.
12. Return JSON only.
13. Do not use Markdown.
14. Do not use code fences.
"""

    response = client.models.generate_content(
        model="gemini-3.7-flash",
        contents=prompt
    )

    return response.text


# ============================================================
# PARSE GEMINI RESPONSE
# ============================================================

def parse_analysis(text):

    if not text:

        raise ValueError(
            "Gemini returned an empty response."
        )

    text = text.strip()

    # Remove Markdown code fences
    text = re.sub(
        r"^```json",
        "",
        text,
        flags=re.IGNORECASE
    )

    text = re.sub(
        r"^```",
        "",
        text
    )

    text = re.sub(
        r"```$",
        "",
        text
    )

    text = text.strip()

    # First attempt
    try:

        return json.loads(text)

    except json.JSONDecodeError:

        # Find JSON object
        start = text.find("{")
        end = text.rfind("}")

        if start == -1 or end == -1:

            raise ValueError(
                "Gemini did not return valid JSON."
            )

        json_text = text[
            start:end + 1
        ]

        return json.loads(
            json_text
        )


# ============================================================
# NORMALIZE AI RESULT
# ============================================================

def normalize_result(data):

    # --------------------------------------------------------
    # VERDICT
    # --------------------------------------------------------

    verdict = str(
        data.get(
            "verdict",
            "UNKNOWN"
        )
    ).upper()

    if verdict not in [
        "SAFE",
        "SUSPICIOUS",
        "MALICIOUS",
        "UNKNOWN"
    ]:

        verdict = "UNKNOWN"

    # --------------------------------------------------------
    # CONFIDENCE
    # --------------------------------------------------------

    confidence = str(
        data.get(
            "confidence",
            "LOW"
        )
    ).upper()

    if confidence not in [
        "LOW",
        "MEDIUM",
        "HIGH"
    ]:

        confidence = "LOW"

    # --------------------------------------------------------
    # RISK SCORE
    # --------------------------------------------------------

    try:

        risk_score = int(
            data.get(
                "risk_score",
                0
            )
        )

    except Exception:

        risk_score = 0

    risk_score = max(
        0,
        min(
            risk_score,
            100
        )
    )

    # --------------------------------------------------------
    # SUMMARY
    # --------------------------------------------------------

    summary = str(
        data.get(
            "summary",
            "No summary available."
        )
    )

    # --------------------------------------------------------
    # EVIDENCE
    # --------------------------------------------------------

    evidence = data.get(
        "evidence",
        []
    )

    if not isinstance(
        evidence,
        list
    ):

        evidence = [
            str(evidence)
        ]

    evidence = [
        str(item)
        for item in evidence
    ]

    # --------------------------------------------------------
    # RISK
    # --------------------------------------------------------

    risk = str(
        data.get(
            "risk",
            "No risk information available."
        )
    )

    # --------------------------------------------------------
    # RECOMMENDATION
    # --------------------------------------------------------

    recommendation = str(
        data.get(
            "recommended_action",
            "No recommendation available."
        )
    )

    return {
        "verdict": verdict,
        "confidence": confidence,
        "risk_score": risk_score,
        "summary": summary,
        "evidence": evidence,
        "risk": risk,
        "recommended_action": recommendation
    }


# ============================================================
# ANALYZE BUTTON
# ============================================================

if st.button(
    "🔍 Analyze Target",
    type="primary",
    use_container_width=True
):

    # ========================================================
    # VALIDATION
    # ========================================================

    valid, error = validate_target(
        target,
        target_type
    )

    if not valid:

        st.error(
            "❌ " + error
        )

        st.stop()

    # ========================================================
    # API KEY CHECK
    # ========================================================

    if not otx_api_key:

        st.error(
            "❌ Enter your AlienVault OTX API key."
        )

        st.stop()

    if not gemini_api_key:

        st.error(
            "❌ Enter your Gemini API key."
        )

        st.stop()

    # ========================================================
    # COLLECT INTELLIGENCE
    # ========================================================

    with st.spinner(
        "🔎 Collecting threat intelligence..."
    ):

        try:

            intelligence = collect_intelligence(
                target.strip(),
                target_type,
                otx_api_key.strip()
            )

        except Exception as e:

            st.error(
                "❌ Intelligence collection failed: "
                + str(e)
            )

            st.stop()

    # ========================================================
    # GEMINI ANALYSIS
    # ========================================================

    with st.spinner(
        "🤖 AI is analyzing the evidence..."
    ):

        try:

            raw_result = analyze_with_gemini(
                target.strip(),
                target_type,
                knowledge_level,
                intelligence,
                gemini_api_key.strip()
            )

            parsed_result = parse_analysis(
                raw_result
            )

            analysis = normalize_result(
                parsed_result
            )

        except Exception as e:

            st.error(
                "❌ AI analysis failed: "
                + str(e)
            )

            st.stop()

    # ========================================================
    # THREAT ASSESSMENT
    # ========================================================

    st.divider()

    st.subheader(
        "🛡️ Threat Assessment"
    )

    verdict = analysis["verdict"]

    confidence = analysis["confidence"]

    risk_score = analysis["risk_score"]

    # ========================================================
    # VERDICT DISPLAY
    # ========================================================

    if verdict == "SAFE":

        verdict_text = "🟢 SAFE"

    elif verdict == "SUSPICIOUS":

        verdict_text = "🟡 SUSPICIOUS"

    elif verdict == "MALICIOUS":

        verdict_text = "🔴 MALICIOUS"

    else:

        verdict_text = "⚪ UNKNOWN"

    # ========================================================
    # METRICS
    # ========================================================

    col1, col2, col3 = st.columns(3)

    with col1:

        st.metric(
            "Verdict",
            verdict_text
        )

    with col2:

        st.metric(
            "Risk Score",
            f"{risk_score}%"
        )

    with col3:

        st.metric(
            "Confidence",
            confidence
        )

    # ========================================================
    # RISK BAR
    # ========================================================

    st.markdown(
        "### 📊 Risk Level"
    )

    st.progress(
        risk_score / 100
    )

    if risk_score < 30:

        st.success(
            f"🟢 Low Risk — {risk_score}%"
        )

    elif risk_score < 70:

        st.warning(
            f"🟡 Medium Risk — {risk_score}%"
        )

    else:

        st.error(
            f"🔴 High Risk — {risk_score}%"
        )

    # ========================================================
    # AI SUMMARY
    # ========================================================

    st.markdown(
        "### 💡 AI Summary"
    )

    st.info(
        analysis["summary"]
    )

    # ========================================================
    # EVIDENCE
    # ========================================================

    st.markdown(
        "### 🔎 Evidence"
    )

    if analysis["evidence"]:

        for item in analysis["evidence"]:

            st.write(
                "• " + item
            )

    else:

        st.write(
            "No significant evidence was found."
        )

    # ========================================================
    # RISK
    # ========================================================

    st.markdown(
        "### ⚠️ Risk"
    )

    st.write(
        analysis["risk"]
    )

    # ========================================================
    # RECOMMENDED ACTION
    # ========================================================

    st.markdown(
        "### 🛡️ Recommended Action"
    )

    st.success(
        analysis["recommended_action"]
    )

    # ========================================================
    # INTELLIGENCE SOURCES
    # ========================================================

    st.markdown(
        "### 📡 Intelligence Sources"
    )

    otx = intelligence.get(
        "AlienVault OTX",
        {}
    )

    dns = intelligence.get(
        "DNS / Host",
        {}
    )

    source1, source2 = st.columns(2)

    with source1:

        if otx.get("status") == "success":

            st.success(
                "✓ AlienVault OTX"
            )

        else:

            st.warning(
                "⚠ AlienVault OTX unavailable"
            )

            if otx.get("message"):

                st.caption(
                    otx["message"]
                )

    with source2:

        if dns.get("status") == "success":

            st.success(
                "✓ DNS / Host"
            )

        else:

            st.warning(
                "⚠ DNS / Host unavailable"
            )

            if dns.get("message"):

                st.caption(
                    dns["message"]
                )

    # ========================================================
    # TECHNICAL DETAILS
    # ========================================================

    with st.expander(
        "🔧 View technical details"
    ):

        st.json(
            intelligence
        )


# ============================================================
# FOOTER
# ============================================================

st.divider()

st.caption(
    "ThreatLens | Passive Threat Intelligence"
)
