
from pathlib import Path
import re

import torch
from flask import Flask, jsonify, request, render_template
from transformers import (
    AutoTokenizer,
    AutoModelForSequenceClassification
)

# ==========================================
# FLASK CONFIGURATION
# ==========================================

app = Flask(__name__)

BASE_DIR = Path(__file__).resolve().parent

MODEL_PATH = (
    BASE_DIR.parent / "scamshield_distilbert_improved"
)

MAX_LENGTH = 256
MAX_INPUT_CHARS = 20000

# ==========================================
# LOAD DISTILBERT MODEL
# ==========================================

device = torch.device(
    "cuda" if torch.cuda.is_available() else "cpu"
)

print("Loading ScamShield AI...")
print("Device:", device)

tokenizer = AutoTokenizer.from_pretrained(
    str(MODEL_PATH)
)

model = AutoModelForSequenceClassification.from_pretrained(
    str(MODEL_PATH)
)

model.to(device)
model.eval()

print("ScamShield AI loaded successfully!")


# ==========================================
# HELPER FUNCTIONS
# ==========================================

def matches(pattern, text):
    return re.search(
        pattern,
        text,
        flags=re.IGNORECASE
    ) is not None


# ==========================================
# SAFETY RULES
# ==========================================

def check_safety_rules(text):

    warnings = []

    # --------------------------------------
    # 1. Fake job payment detection
    # --------------------------------------

    job_context = matches(
        r"\b(job|hired|hiring|recruitment|"
        r"joining|offer letter|position|"
        r"employment|selected|shortlisted|"
        r"interview)\b",
        text
    )

    fee_context = matches(
        r"\b(registration fee|verification fee|"
        r"processing fee|security deposit|"
        r"joining fee|document verification|"
        r"refundable deposit)\b",
        text
    )

    payment_action = matches(
        r"\b(pay|transfer|send|deposit|"
        r"submit|make a payment)\b",
        text
    )

    money_amount = matches(
        r"(?:\brs\.?\s*|₹\s*)\d+",
        text
    )

    if job_context and (
        fee_context or (
            payment_action and money_amount
        )
    ):
        warnings.append(
            "This job-related message may request "
            "an upfront payment."
        )

    # --------------------------------------
    # 2. OTP / PIN / password requests
    # --------------------------------------

    credential_request = matches(
        r"\b(share|send|reply with|provide|"
        r"tell us|enter|submit|give|"
        r"confirm|verify)\b"
        r".{0,60}"
        r"\b(otp|one.time password|"
        r"verification code|upi pin|"
        r"banking pin|password)\b",
        text
    )

    if credential_request:
        warnings.append(
            "This message may request sensitive "
            "authentication information."
        )

    return warnings


# ==========================================
# BANKING CONTEXT REVIEW
# ==========================================

def check_banking_context(text):

    # Identify transaction-style notifications.
    # This does NOT verify the sender or bank.

    banking_context = matches(
        r"\b(bank|account|transaction|"
        r"upi|payment|card)\b",
        text
    )

    transaction_context = matches(
        r"\b(debited|credited|paid|"
        r"payment successful|"
        r"payment of|"
        r"transaction successful|"
        r"transaction reference|"
        r"transaction id|"
        r"spent)\b",
        text
    )

    amount_context = matches(
        r"(?:\brs\.?\s*|₹\s*)"
        r"[\d,]+(?:\.\d{1,2})?",
        text
    )

    # Instructions commonly found in scams.
    # Keep these messages out of the
    # banking review downgrade.

    credential_terms = matches(
        r"\b(otp|one.time password|"
        r"verification code|upi pin|"
        r"banking pin|password|"
        r"cvv)\b",
        text
    )

    risky_instructions = matches(
        r"\b(click|open|visit|follow|"
        r"transfer|send money|"
        r"pay a fee|pay now|"
        r"share|provide|"
        r"reply with|enter your|"
        r"submit your|"
        r"account blocked|"
        r"account suspended|"
        r"account locked|"
        r"reactivate|"
        r"urgent verification)\b",
        text
    )

    contains_link = matches(
        r"(https?://|www\.)",
        text
    )

    looks_like_transaction_notice = (
        banking_context
        and transaction_context
        and amount_context
    )

    has_high_risk_signals = (
        credential_terms
        or risky_instructions
        or contains_link
    )

    return (
        looks_like_transaction_notice
        and not has_high_risk_signals
    )


# ==========================================
# HOME PAGE
# ==========================================

@app.route("/")
def home():
    return render_template("index.html")


# ==========================================
# HEALTH CHECK
# ==========================================

@app.route("/api/health", methods=["GET"])
def health():

    return jsonify({
        "status": "ok",
        "model": "scamshield_distilbert_improved",
        "device": str(device)
    })


# ==========================================
# SCAM PREDICTION API
# ==========================================

@app.route("/api/predict", methods=["POST"])
def predict():

    data = request.get_json(silent=True)

    if not isinstance(data, dict):
        return jsonify({
            "error": "Please send a JSON object."
        }), 400

    text = data.get("text")

    if not isinstance(text, str) or not text.strip():
        return jsonify({
            "error": "Please enter a message to analyze."
        }), 400

    text = text.strip()

    if len(text) > MAX_INPUT_CHARS:
        return jsonify({
            "error": (
                "Message is too long. "
                "Maximum 20,000 characters."
            )
        }), 400

    # --------------------------------------
    # DistilBERT prediction
    # --------------------------------------

    inputs = tokenizer(
        text,
        return_tensors="pt",
        truncation=True,
        max_length=MAX_LENGTH
    ).to(device)

    with torch.inference_mode():

        outputs = model(**inputs)

        probabilities = torch.softmax(
            outputs.logits,
            dim=-1
        )[0]

    scam_probability = float(
        probabilities[1].item()
    )

    predicted_label = int(
        torch.argmax(probabilities).item()
    )

    # --------------------------------------
    # Safety checks
    # --------------------------------------

    warnings = check_safety_rules(text)

    banking_review = check_banking_context(text)

    # --------------------------------------
    # Final classification
    # --------------------------------------

    if predicted_label == 1:

        if banking_review and not warnings:

            result = "Suspicious - Review Required"

            warnings.append(
                "This resembles a banking transaction "
                "notification, but the AI model flagged "
                "it as a scam. Verify the transaction "
                "through your bank's official app."
            )

        else:

            result = "Potential Scam"

    elif warnings:

        result = "Suspicious - Review Required"

    else:

        result = "Likely Legitimate"

    # --------------------------------------
    # Return results
    # --------------------------------------

    return jsonify({

        "result": result,

        "prediction": predicted_label,

        "scam_probability": round(
            scam_probability, 4
        ),

        "safety_warnings": warnings,

        "requires_review": (
            result == "Suspicious - Review Required"
        ),

        "banking_review": banking_review,

        "message": (
            "This is an AI prediction, not a guarantee. "
            "Do not share passwords, OTPs, UPI PINs "
            "or financial details based only on "
            "this result. Verify suspicious messages "
            "through official channels."
        )
    })


# ==========================================
# RUN APPLICATION
# ==========================================

if __name__ == "__main__":

    app.run(
        host="127.0.0.1",
        port=5000,
        debug=False
    )
