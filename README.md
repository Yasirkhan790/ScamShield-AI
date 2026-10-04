# ScamShield AI V2

**Before You Click, Ask ScamShield.**

ScamShield AI V2 is a hybrid, multi-agent, explainable scam-risk assessment platform built for the **Pak Angels Generative & Agentic AI Training — Cohort 11 Final Hackathon**.

It analyzes suspicious:

- Messages
- URLs
- Screenshots

and combines deterministic rules, a trained local machine-learning classifier, semantic AI when available, taxonomy-based evidence fusion, deterministic risk scoring, and automated safety guidance.

ScamShield is designed as a security-assistance and educational system. It does not claim that any message, website, or screenshot is guaranteed to be malicious or safe.

---

# Live Deployment

Frontend:

```text
https://scam-shield-ai-5tzh.vercel.app
```

Backend API:

```text
https://scamshield-ai-production-6689.up.railway.app
```

API documentation:

```text
https://scamshield-ai-production-6689.up.railway.app/docs
```

Health endpoint:

```text
https://scamshield-ai-production-6689.up.railway.app/api/health
```

> Verify that the V2 Railway and Vercel deployments are active before final hackathon submission.

---

# Project Version

```text
ScamShield AI V2
API Version: 2.0.0
ML Model: scamshield-text-v2-release-1
Taxonomy Version: 2.0
Frozen ML Threshold: 0.42
```

---

# Problem

Digital scams increasingly use social engineering rather than obvious scam keywords.

A scammer may avoid writing:

```text
Send me your OTP.
```

and instead write:

```text
Tell me the six-digit security code that was just sent to your phone.
```

Traditional keyword-only systems can miss such paraphrases.

At the same time, a system must avoid flagging legitimate security advice such as:

```text
Never share your OTP or password with anyone.
```

ScamShield AI V2 addresses both problems by combining multiple types of evidence instead of relying on a single keyword list or a single LLM response.

---

# Core Objective

ScamShield aims to answer four questions:

1. **What suspicious behavior is present?**
2. **How strong is the evidence?**
3. **Why did the system assign this risk level?**
4. **What should the user safely do next?**

The final risk score is controlled by deterministic application logic.

The LLM and ML model provide supporting evidence but do not directly invent the final numerical risk score.

---

# Main Features

## Message Scanner

Analyzes suspicious:

- SMS
- Email
- WhatsApp messages
- Social-media messages
- Job offers
- Investment offers
- Prize notifications
- Account alerts
- Payment requests
- Credential requests

The message pipeline combines:

```text
Deterministic Rules
+
Trained ML
+
Optional Semantic AI
+
V2 Scam Taxonomy
+
Mitigation Detection
+
Evidence Fusion
+
Deterministic Risk Scoring
```

---

## URL Scanner

Analyzes the submitted URL string without visiting the destination website.

Signals include:

- HTTP vs HTTPS
- IP-address hosts
- URL shorteners
- Excessive subdomains
- Punycode
- Suspicious paths
- Brand/domain mismatch
- Misleading subdomains
- Encoded URLs
- Unusual ports
- Credential-oriented paths

ScamShield does **not** claim live website reputation checking or live malware scanning.

---

## Screenshot Scanner

Supports:

- PNG
- JPG
- JPEG
- WEBP

Maximum default upload size:

```text
5 MB
```

Screenshot flow:

```text
Screenshot
    ↓
Validate file type and size
    ↓
Try multimodal AI text extraction
    ↓
If unavailable:
Local Tesseract OCR fallback
    ↓
Extract visible text
    ↓
Run the same ScamShield V2 message pipeline
    ↓
Rules + ML + Taxonomy + Evidence Fusion
    ↓
Deterministic Risk Agent
    ↓
Safety Automation
    ↓
Explainable Final Report
```

Raw screenshot image bytes are not stored in history.

---

# Multi-Agent Architecture

ScamShield V2 is not:

```text
User → LLM → Answer
```

Instead it uses bounded specialized agents.

```text
                         ┌─────────────────────────┐
                         │       User Input        │
                         └────────────┬────────────┘
                                      │
                                      ▼
                     ┌─────────────────────────────┐
                     │ Orchestrator / Router Agent │
                     └────────────┬────────────────┘
                                  │
              ┌───────────────────┼───────────────────┐
              │                   │                   │
              ▼                   ▼                   ▼
      ┌───────────────┐   ┌─────────────┐   ┌────────────────┐
      │ Message Agent │   │  URL Agent  │   │  Vision Agent  │
      └───────┬───────┘   └──────┬──────┘   └────────┬───────┘
              │                  │                   │
              └──────────────────┼───────────────────┘
                                 │
                                 ▼
                  ┌────────────────────────────┐
                  │ Evidence Collection Layer  │
                  │                            │
                  │ • Deterministic Rules      │
                  │ • Trained ML               │
                  │ • Optional Semantic AI     │
                  │ • URL Heuristics           │
                  │ • OCR / Image Extraction   │
                  └────────────┬───────────────┘
                               │
                               ▼
                  ┌────────────────────────────┐
                  │ Evidence Fusion Agent      │
                  └────────────┬───────────────┘
                               │
                               ▼
                  ┌────────────────────────────┐
                  │ V2 Indicator Taxonomy      │
                  │ + Mitigating Context       │
                  └────────────┬───────────────┘
                               │
                               ▼
                  ┌────────────────────────────┐
                  │ Deterministic Risk Agent   │
                  └────────────┬───────────────┘
                               │
                               ▼
                  ┌────────────────────────────┐
                  │ Safety / Automation Agent  │
                  └────────────┬───────────────┘
                               │
                               ▼
                  ┌────────────────────────────┐
                  │ Explainable Final Report   │
                  └────────────────────────────┘
```

---

# Agents

## 1. Orchestrator / Router Agent

Selects the correct specialized agent based on the input type.

Routes input to:

- Message Agent
- URL Agent
- Vision Agent

The actual execution path is returned to the frontend as a real backend agent trace.

---

## 2. Message Agent

Coordinates:

- Deterministic scam rules
- Local ML inference
- Semantic AI when available
- Taxonomy normalization
- Evidence fusion
- Risk calculation
- Safety automation

---

## 3. URL Agent

Coordinates:

- URL validation
- Structural heuristics
- Brand/domain mismatch signals
- Taxonomy mapping
- Risk scoring
- Safety guidance

The URL Agent does not visit the submitted destination.

---

## 4. Vision Agent

Coordinates screenshot analysis.

It:

1. Validates the image
2. Extracts visible text
3. Sends the extracted text into the normal V2 message pipeline
4. Returns the extraction provider and analysis trace

---

## 5. Evidence Fusion Agent

Combines evidence from:

- Deterministic rules
- ML classifier
- Semantic AI observations
- URL heuristics
- Taxonomy normalization
- Mitigating context

It normalizes different wording into stable semantic indicators.

Example:

```text
OTP
verification code
security code
six-digit code
confirmation digits
```

can all represent the same credential-theft behavior.

---

## 6. Risk Agent

Produces the final deterministic application-defined risk score.

Important:

- The ML model does not directly control the final risk score.
- The LLM does not directly control the final risk score.
- Fixed deterministic application rules control the final score.

This improves consistency and explainability.

---

## 7. Safety / Automation Agent

Triggered for:

```text
HIGH
CRITICAL
```

risk cases.

It creates a structured incident report containing:

- Risk level
- Risk score
- Scam category
- Evidence
- Escalation reason
- Immediate recommended actions

The agent does not perform dangerous or irreversible external actions.

It does not automatically:

- Contact police
- Contact banks
- Send money
- Block accounts
- Open suspicious links

---

# Real Backend Agent Trace

The frontend can display the actual backend execution path.

Example:

```text
1. Orchestrator / Router Agent
2. Message Agent
3. Deterministic Rules
4. ML Classifier
5. Semantic AI
6. Evidence Fusion Agent
7. Risk Agent
8. Safety / Automation Agent
```

This trace represents real backend processing rather than a purely visual animation.

---

# Trained Machine-Learning Model

ScamShield V2 includes a frozen local text classifier.

Model version:

```text
scamshield-text-v2-release-1
```

Architecture:

```text
Text
 ↓
Word TF-IDF
  • 1–3 word n-grams
  • up to 35,000 features

+

Character TF-IDF
  • character word-boundary 3–6 grams
  • up to 30,000 features

 ↓
Feature Union
 ↓
Logistic Regression
 ↓
Scam / Legitimate score
```

Classifier configuration includes:

```text
Logistic Regression
class_weight = balanced
solver = liblinear
C = 2.0
random_state = 42
```

---

# Frozen ML Threshold

The final selected classification threshold is:

```text
0.42
```

The threshold was selected using the validation set only.

Selection criterion:

```text
Highest scam-class F1 among thresholds
with scam recall >= 0.85
```

The release holdout was evaluated only after the threshold was frozen.

---

# Final ML Evaluation

## Final Release Holdout

Records:

```text
3,275
```

Results:

| Metric          |     Result |
| --------------- | ---------: |
| Accuracy        | **98.26%** |
| Scam Precision  | **97.29%** |
| Scam Recall     | **97.00%** |
| Scam F1         | **97.14%** |
| True Negatives  |       2249 |
| False Positives |         27 |
| False Negatives |         30 |
| True Positives  |        969 |

Frozen threshold:

```text
0.42
```

These are held-out release evaluation results for the current frozen classifier.

The ML score shown by the application is supporting model evidence and should **not** be interpreted as a verified real-world probability that a message is fraudulent.

---

# Final Validation Results

Validation records:

```text
3,193
```

| Metric         |     Result |
| -------------- | ---------: |
| Accuracy       | **98.84%** |
| Scam Precision | **97.25%** |
| Scam Recall    | **98.82%** |
| Scam F1        | **98.03%** |

---

# Robustness Challenge

A separate development robustness suite contained 10 targeted examples covering cases such as:

- Direct OTP requests
- Credential paraphrases
- Security-code paraphrases
- Prize + fee scams
- Job scams
- Investment scams
- Fake account alerts
- Legitimate security warnings
- Normal benign messages

Final challenge result:

```text
9 / 10 passed
```

This challenge suite was used during development and is not presented as a blind statistical evaluation.

---

# Data-Splitting and Leakage Protection

ScamShield V2 includes explicit controls intended to reduce data leakage.

Final release preparation included:

- Cleaning
- Label normalization
- Exact duplicate removal
- Template duplicate handling
- Near-duplicate analysis
- Group-aware splitting
- Separate train, validation, and release holdout sets
- Hardening examples restricted from protected evaluation splits

Near-duplicate similarity threshold:

```text
0.92
```

Final recorded cross-split duplicate-group leakage:

```text
0
```

Final training records:

```text
15,170
```

Reviewed hardening records:

```text
88
```

Validation records:

```text
3,193
```

Release holdout records:

```text
3,275
```

---

# Research Data Sources

The V2 research pipeline uses multiple labeled datasets rather than relying on one source.

Research inputs include datasets covering:

- SMS spam/scam messages
- Phishing emails
- Legitimate emails
- Phishing URLs
- Legitimate URLs
- Reviewed hardening examples

Dataset acquisition and preparation scripts are located under:

```text
research/scripts/
```

Raw large datasets are intentionally excluded from Git where appropriate.

---

# Scam Indicator Taxonomy

Taxonomy version:

```text
2.0
```

The taxonomy organizes suspicious behaviors into semantic categories.

Major categories include:

- Social engineering
- Credential theft
- Financial fraud
- Impersonation
- Account takeover
- Job scams
- Investment scams
- Prize scams
- Romance scams
- Malware and device-access scams
- Identity theft
- Delivery scams
- Marketplace scams
- Loan scams
- Charity scams
- URL risk

Example indicators include:

```text
urgency
time_pressure
fear_or_threat
otp_request
verification_code_request
password_request
card_details_request
release_fee
registration_fee
guaranteed_job
guaranteed_returns
unexpected_prize
remote_access_request
cnic_request
fake_tracking_link
brand_domain_mismatch
typosquatting
```

Taxonomy file:

```text
backend/app/knowledge/indicator_taxonomy.json
```

---

# Mitigating Indicators

ScamShield does not treat every suspicious keyword as malicious.

It also detects legitimate context such as:

```text
security_education_context
user_reporting_scam
quoted_scam_example
never_share_otp_warning
expected_transaction_confirmation
user_initiated_verification
legitimate_security_advice
```

Example:

```text
Never share your OTP or password with anyone.
```

contains scam-related vocabulary, but the message is a security warning.

Mitigation handling helps reduce false positives.

---

# Evidence Fusion

The final decision may combine:

```text
Deterministic rule evidence
+
ML evidence
+
Optional semantic AI observations
+
Taxonomy-normalized indicators
+
Mitigating indicators
```

The Evidence Fusion Agent records:

- Taxonomy version
- Normalized indicators
- Mitigating indicators
- Evidence sources
- Risk adjustments

This information is returned to the frontend for explainability.

---

# Risk Levels

ScamShield uses four application-defined risk bands:

```text
0–29    LOW
30–59   MEDIUM
60–79   HIGH
80–100  CRITICAL
```

The risk score is an application-defined security indicator.

It is **not** a calibrated fraud probability.

---

# Explainable Output

A message result can contain:

```text
Risk score
Risk level
Primary category
Secondary categories
Raw deterministic indicators
Normalized taxonomy indicators
Mitigating indicators
ML status
ML model version
ML scam score
Frozen ML threshold
Semantic AI status
AI observations
Evidence sources
Risk adjustments
Real agent trace
Incident report
Recommended actions
Disclaimer
```

---

# AI Integration

Semantic AI is optional.

Supported architecture includes:

- Gemini-style provider
- OpenAI-compatible provider abstraction

When configured, AI can contribute:

- Semantic interpretation
- Scam-category enrichment
- Structured observations
- Explanations
- Safety recommendations

AI does not directly assign the final numeric risk score.

---

# AI Fallback

If the external AI provider:

- Is disabled
- Returns invalid JSON
- Times out
- Hits quota limits
- Returns a provider error

ScamShield continues using its local components where possible.

For message analysis:

```text
Rules
+
Local ML
+
Taxonomy
+
Evidence Fusion
+
Risk Agent
```

remain available without an external LLM.

---

# Screenshot OCR Fallback

ScamShield supports two screenshot text-extraction paths.

## Path 1 — Multimodal AI

When a compatible multimodal AI provider is available:

```text
Image
→ multimodal text extraction
→ ScamShield V2 text pipeline
```

## Path 2 — Local Tesseract OCR

When local OCR is enabled:

```text
Image
→ Pillow preprocessing
→ Tesseract OCR
→ extracted text
→ ScamShield V2 text pipeline
```

The Docker backend installs:

```text
tesseract-ocr
```

Python dependencies include:

```text
Pillow
pytesseract
```

---

# Supported Screenshot Formats

Accepted formats:

```text
PNG
JPG
JPEG
WEBP
```

Default maximum upload:

```text
5 MB
```

Very large decoded images are also restricted in the local OCR pipeline.

---

# API Endpoints

## Health

```http
GET /api/health
```

Reports:

- API version
- AI readiness
- OCR readiness
- Screenshot readiness
- ML readiness
- ML model version
- Frozen threshold
- Available capabilities

---

## Message Analysis

```http
POST /api/analyze/message
Content-Type: application/json
```

Example:

```json
{
  "message": "Send your OTP immediately to verify your account."
}
```

---

## URL Analysis

```http
POST /api/analyze/url
Content-Type: application/json
```

Example:

```json
{
  "url": "https://paypal.security-check.example.com/login"
}
```

---

## Screenshot Analysis

```http
POST /api/analyze/screenshot
Content-Type: multipart/form-data
```

Form field:

```text
file
```

---

## History

```http
GET /api/history?limit=20
```

```http
GET /api/history/{id}
```

---

# Project Structure

```text
ScamShield-AI/
│
├── backend/
│   ├── app/
│   │   ├── agents/
│   │   │   ├── orchestrator.py
│   │   │   ├── scamshield_agent.py
│   │   │   ├── message_agent.py
│   │   │   ├── url_agent.py
│   │   │   ├── vision_agent.py
│   │   │   ├── evidence_fusion_agent.py
│   │   │   ├── risk_agent.py
│   │   │   └── safety_automation_agent.py
│   │   │
│   │   ├── ai/
│   │   │
│   │   ├── api/
│   │   │   ├── analysis.py
│   │   │   └── history.py
│   │   │
│   │   ├── database/
│   │   │
│   │   ├── knowledge/
│   │   │   └── indicator_taxonomy.json
│   │   │
│   │   ├── ml/
│   │   │   ├── artifacts/
│   │   │   │   └── scamshield_text_model.joblib
│   │   │   ├── classifier.py
│   │   │   └── metadata.json
│   │   │
│   │   ├── models/
│   │   │   └── analysis.py
│   │   │
│   │   ├── services/
│   │   │   ├── message_analysis_service.py
│   │   │   ├── url_analysis_service.py
│   │   │   ├── screenshot_analysis_service.py
│   │   │   └── local_ocr_service.py
│   │   │
│   │   ├── tools/
│   │   │
│   │   └── main.py
│   │
│   ├── tests/
│   ├── Dockerfile
│   └── requirements.txt
│
├── frontend/
│   ├── src/
│   │   ├── services/
│   │   │   └── api.js
│   │   ├── App.jsx
│   │   ├── main.jsx
│   │   └── styles.css
│   │
│   └── package.json
│
├── research/
│   ├── data/
│   ├── models/
│   ├── reports/
│   ├── schemas/
│   └── scripts/
│
├── docs/
├── .env.example
├── .gitignore
├── docker-compose.yml
└── README.md
```

---

# Technology Stack

## Frontend

- React
- Vite
- JavaScript
- Lucide React
- CSS

## Backend

- Python
- FastAPI
- Pydantic
- Uvicorn
- SQLite

## Machine Learning

- scikit-learn
- TF-IDF
- Logistic Regression
- Joblib
- NumPy
- Pandas

## OCR

- Tesseract OCR
- pytesseract
- Pillow

## AI

- Gemini-compatible provider support
- OpenAI-compatible provider abstraction
- Structured JSON validation
- Safe fallback handling

## Deployment

- Railway
- Vercel
- Docker

---

# Local Setup

## 1. Clone the repository

```bash
git clone https://github.com/Yasirkhan790/ScamShield-AI.git
cd ScamShield-AI
```

For the V2 development branch:

```bash
git checkout v2-accuracy
```

---

# Environment Configuration

Create `.env` from `.env.example`.

Windows CMD:

```cmd
copy .env.example .env
```

PowerShell:

```powershell
Copy-Item .env.example .env
```

Linux/macOS:

```bash
cp .env.example .env
```

Default example:

```env
AI_PROVIDER=disabled
AI_API_KEY=
AI_BASE_URL=
AI_TIMEOUT_SECONDS=15

DATABASE_URL=sqlite:///./scamshield.db

SCREENSHOT_MAX_BYTES=5242880

CORS_ORIGINS=http://localhost:5173,http://localhost:8080

ML_ENABLED=true
ML_MODEL_PATH=

LOCAL_OCR_ENABLED=false
```

Never commit a real API key.

---

# Backend Setup

```bash
cd backend
```

Create a virtual environment:

```bash
python -m venv .venv
```

Windows CMD:

```cmd
.venv\Scripts\activate
```

PowerShell:

```powershell
.venv\Scripts\Activate.ps1
```

Linux/macOS:

```bash
source .venv/bin/activate
```

Install requirements:

```bash
python -m pip install --upgrade pip
pip install -r requirements.txt
```

Start:

```bash
python -m uvicorn app.main:app --reload
```

Backend:

```text
http://127.0.0.1:8000
```

API docs:

```text
http://127.0.0.1:8000/docs
```

Health:

```text
http://127.0.0.1:8000/api/health
```

---

# Frontend Setup

Open another terminal:

```bash
cd frontend
npm install
npm run dev
```

Frontend:

```text
http://localhost:5173
```

Production build:

```bash
npm run build
```

---

# Local OCR Setup

The Python package `pytesseract` is not the OCR engine itself.

Local screenshot OCR requires the **Tesseract executable**.

With:

```env
LOCAL_OCR_ENABLED=false
```

the local OCR fallback is disabled.

To use local OCR, install Tesseract on the operating system and set:

```env
LOCAL_OCR_ENABLED=true
```

The backend Docker image installs Tesseract automatically.

---

# Docker

Backend Docker image:

```text
python:3.12-slim
```

It installs:

```text
tesseract-ocr
```

Build/run through Docker Compose where configured:

```bash
docker compose up --build
```

---

# Railway Deployment

Recommended backend variables:

```env
AI_PROVIDER=disabled

LOCAL_OCR_ENABLED=true

ML_ENABLED=true

DATABASE_URL=sqlite:////data/scamshield.db

SCREENSHOT_MAX_BYTES=5242880

CORS_ORIGINS=https://scam-shield-ai-5tzh.vercel.app,http://localhost:5173
```

Recommended Railway service root:

```text
/backend
```

Recommended SQLite volume mount:

```text
/data
```

Production health should report:

```text
status = ok
version = 2.0.0
ml_ready = true
local_ocr_enabled = true
local_ocr_ready = true
screenshot_ready = true
```

---

# Vercel Deployment

Frontend root:

```text
frontend
```

Production environment variable:

```env
VITE_API_BASE_URL=https://scamshield-ai-production-6689.up.railway.app
```

Do not append `/api`.

---

# History and Privacy

ScamShield stores analysis history using SQLite.

The application is designed to store sanitized previews rather than unnecessary raw sensitive information.

For screenshots:

- Raw image bytes are not saved in history.
- Extracted text is passed into the normal analysis pipeline.
- The history layer stores the resulting sanitized analysis representation.

---

# Testing

Run:

```bash
cd backend
python -m pytest -q
```

Current verified backend result:

```text
51 passed
```

One dependency deprecation warning may appear from Starlette/AnyIO. It does not currently indicate a ScamShield test failure.

Coverage includes:

- Message analysis
- URL analysis
- Screenshot analysis
- API routes
- History
- Structured AI handling
- AI fallback
- Deterministic risk scoring
- ML integration
- Agent orchestration
- Evidence fusion
- Mitigating context
- Incident automation
- Release cases
- Legitimate controls

---

# Demo Cases

## Fake Bank / Credential Theft

```text
URGENT: Your bank account has been suspended.
Send your password and OTP immediately.
```

Expected behavior:

```text
Strong risk
Credential/account takeover indicators
ML scam evidence
Agent trace
Incident automation when HIGH/CRITICAL
```

---

## Security-Code Paraphrase

```text
Tell me the six-digit security code that was just sent to your phone.
```

Expected taxonomy indicator:

```text
verification_code_request
```

This demonstrates semantic normalization beyond literal `OTP` matching.

---

## Prize Scam

```text
Congratulations. You won a cash reward.
Pay the release fee today to claim it.
```

Expected evidence can include:

```text
unexpected_prize
release_fee
```

---

## Job Scam

```text
Work from home with guaranteed hiring.
Pay the registration fee today to start.
```

---

## Investment Scam

```text
Guaranteed 300 percent return in seven days.
There is no risk. Deposit your money today.
```

---

## Legitimate Security Advice

```text
Never share your OTP or password with anyone.
```

Expected:

```text
LOW
```

with mitigating context.

---

## URL Example

```text
https://paypal.security-check.example.com/login
```

Expected to trigger suspicious domain/subdomain analysis without visiting the destination.

---

## Screenshot Example

Create a screenshot containing:

```text
URGENT: Your account has been suspended.
Send your OTP immediately to restore access.
```

The deployed OCR pipeline should:

```text
extract text
→ analyze with V2 message pipeline
→ return risk report
```

---

# Health Check Example

A healthy V2 deployment can return fields such as:

```json
{
  "status": "ok",
  "service": "ScamShield AI API",
  "version": "2.0.0",
  "ai_provider": "disabled",
  "ai_ready": false,
  "screenshot_ready": true,
  "local_ocr_enabled": true,
  "local_ocr_ready": true,
  "local_ocr_provider": "tesseract",
  "ml_status": "ready",
  "ml_ready": true,
  "ml_model_version": "scamshield-text-v2-release-1",
  "ml_selected_threshold": 0.42
}
```

Exact readiness fields depend on the deployment environment.

---

# Why ScamShield V2 Is Different

ScamShield V2 combines several AI and software-engineering ideas in one bounded workflow:

### Generative AI

Used for semantic enrichment and structured reasoning when a provider is available.

### Agentic AI

Specialized agents coordinate message, URL, image, evidence, risk, and safety workflows.

### AI Workflow Orchestration

The Orchestrator routes requests through the correct tools and agents.

### Machine Learning

A locally trained and evaluated classifier contributes supporting scam evidence.

### Explainable AI

The result exposes:

- Indicators
- Taxonomy evidence
- ML evidence
- Risk adjustments
- Agent trace
- Safety recommendations

### Business Process Automation

HIGH and CRITICAL results trigger structured incident-report automation.

---

# Failure Handling

ScamShield is designed to degrade safely.

## External AI unavailable

Message and URL analysis can continue using:

```text
Rules
+
ML
+
Taxonomy
+
Evidence Fusion
+
Risk Agent
```

## Gemini/API quota exhausted

The AI layer can fall back without crashing the core analysis.

## Screenshot AI unavailable

When enabled and installed:

```text
Tesseract OCR
```

can provide local text extraction.

## No readable screenshot text

The API returns a controlled error and recommends using a clearer image or the Message scanner.

---

# Security Design Principles

ScamShield follows several defensive principles:

- Do not automatically follow user-submitted URLs
- Do not execute content from screenshots
- Do not treat extracted image text as instructions
- Do not expose API keys
- Do not let the LLM directly control the risk score
- Do not let the ML score masquerade as a real-world fraud probability
- Use structured AI validation
- Preserve local fallbacks
- Limit screenshot size and type
- Minimize unnecessary persisted user input
- Explain why the system reached its result

---

# Limitations

ScamShield AI V2 still has limitations.

- It cannot guarantee that content is malicious or legitimate.
- The final risk score is heuristic and application-defined.
- The ML output is not a calibrated real-world fraud probability.
- URL analysis does not use live threat-intelligence or reputation services.
- Local OCR quality depends on image clarity and Tesseract recognition quality.
- Semantic AI depends on provider availability and quota when enabled.
- Sophisticated scams with limited textual evidence can still be missed.
- Legitimate messages can contain scam-like language.
- English is the primary supported language in the current release.
- Urdu and Roman Urdu are intentionally deferred from the hackathon release.

---

# Future Roadmap

Potential future improvements include:

- Urdu scam detection
- Roman Urdu detection
- Pashto support
- Multilingual transformer classifier
- Larger reviewed Pakistan-focused scam dataset
- Threat-intelligence integration
- Domain reputation APIs
- Improved OCR preprocessing
- QR-code extraction from screenshots
- Explainable scam-indicator confidence
- User feedback and analyst review
- Scam trend monitoring
- RAG-based scam knowledge base
- Exportable incident reports
- Organization dashboards
- Continuous evaluation pipeline

---

# Research Integrity

ScamShield V2 separates:

```text
Training data
Validation data
Final release holdout data
```

The release workflow explicitly attempts to avoid:

- Threshold tuning on the final holdout
- Duplicate leakage across splits
- Near-duplicate leakage
- Repeated final-test optimization

The final release holdout metrics were saved as a frozen evaluation artifact.

Research reports are available under:

```text
research/reports/
```

---

# Model Artifact

Production model:

```text
backend/app/ml/artifacts/scamshield_text_model.joblib
```

Model metadata:

```text
backend/app/ml/metadata.json
```

Current model SHA-256 recorded by the release process:

```text
97591919ddf5f47077778c61d3e14b84422c1374a8b17fba291a37d0f4a29a1d
```

---

# Release Branch

Current V2 development/release branch:

```text
v2-accuracy
```

Recommended final hackathon tag after production verification:

```text
v2-hackathon-final
```

---

# Final Verification Checklist

Before submitting the hackathon project:

- [ ] Backend tests pass
- [ ] Frontend production build passes
- [ ] ML health reports ready
- [ ] Railway API reports V2
- [ ] Tesseract OCR reports ready in production
- [ ] Screenshot scanner works
- [ ] Message scanner works
- [ ] URL scanner works
- [ ] False-positive mitigation case stays LOW
- [ ] Real agent trace appears in UI
- [ ] ML evidence appears in UI
- [ ] Evidence Fusion panel appears
- [ ] HIGH/CRITICAL incident report appears
- [ ] History works
- [ ] Vercel connects to Railway
- [ ] No API keys exist in Git
- [ ] README links are verified
- [ ] Demo script is rehearsed
- [ ] Git tag is created

---

# Hackathon Context

Built for:

```text
Pak Angels
Generative & Agentic AI Training
Cohort 11
Final / 2nd Hackathon
```

The project demonstrates multiple skills from the program:

- Generative AI
- Agentic AI
- AI workflows
- Multi-agent coordination
- Machine learning
- AI-powered process automation

---

# Disclaimer

ScamShield AI is an educational and security-assistance project.

It should not be used as the sole basis for financial, legal, law-enforcement, or account-security decisions.

Always independently verify suspicious communications through official and trusted channels.

---

# Final Message

ScamShield does not simply ask an LLM whether something looks suspicious.

It combines:

```text
Deterministic security rules
+
Trained machine learning
+
Optional semantic AI
+
Multi-agent orchestration
+
Taxonomy normalization
+
Mitigation handling
+
Evidence fusion
+
Deterministic risk scoring
+
Safety automation
```

to produce a transparent and actionable risk assessment.

## Before You Click, Ask ScamShield.
