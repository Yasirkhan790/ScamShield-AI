# ScamShield AI

Before You Click, Ask ScamShield.

ScamShield AI is an explainable, AI-assisted scam-risk assessment web application built for a 2-day hackathon. It analyzes suspicious messages, URLs, and screenshots, identifies warning signals, calculates an application-defined risk score, and gives clear safety actions.

ScamShield is an educational and security-assistance tool. It does not claim guaranteed scam detection or guaranteed safety.

## Final hackathon release status

Core hackathon MVP is implemented and frozen as final hackathon release `1.0.0`.

Working features:

- Message scanner
- URL scanner
- Screenshot scanner
- PNG, JPG/JPEG, and WEBP validation
- Multimodal screenshot text extraction when an AI provider is configured
- Agentic analysis workflow
- Deterministic red-flag detection
- Deterministic risk score from 0 to 100
- Four risk levels: LOW, MEDIUM, HIGH, CRITICAL
- Scam category classification
- Optional structured LLM enrichment
- Strict AI JSON validation
- Safe deterministic fallback when AI fails or is disabled
- Explainable indicators and scoring weights
- Safety recommendations
- SQLite analysis history
- Privacy-safe history previews
- Demo sample cases
- Staged analysis progress UI
- API health indicator
- About / architecture page
- Docker deployment configuration with same-origin API proxy and health checks
- Responsive React interface
- Release smoke-check command
- 10 scam, 5 legitimate, and 5 edge-case release corpus

## Why the architecture matters

ScamShield is not a simple `User → LLM → Response` application.

```text
User
  ↓
Input Processor
  ↓
ScamShield Agent
  ↓
Analysis Router
  ├── Message Analysis
  ├── URL Analysis
  └── Screenshot Text Extraction
  ↓
Deterministic Signal Detection
  ↓
Risk Engine
  ↓
Optional Structured AI Enrichment
  ↓
Safety Advisor
  ↓
Final Report
```

The LLM helps with explanation, classification, observations, and recommendations. It does not control the numerical risk score.

## Supported scam categories

- Phishing
- Impersonation
- Payment Scam
- Job Scam
- Investment Scam
- Prize/Lottery Scam
- Romance Scam
- Account Takeover
- Delivery/Package Scam
- Other / Suspicious

## Risk levels

```text
0–29   LOW
30–59  MEDIUM
60–79  HIGH
80–100 CRITICAL
```

Risk scoring is application-defined and should not be interpreted as a scientifically validated probability.

## Demo cases

The Message scanner includes five judge-ready examples:

1. Fake bank phishing
2. Prize scam
3. Job scam
4. Investment scam
5. Legitimate low-risk control

The URL scanner includes:

- Normal HTTPS URL
- IP-address login URL
- Brand-mismatch URL
- Shortened verification URL

See `docs/FINAL_DEMO_SCRIPT.md` for the final 3-minute demo script and `docs/PHASE_8.md` for final release verification.

## API endpoints

```text
GET  /api/health
POST /api/analyze/message
POST /api/analyze/url
POST /api/analyze/screenshot
GET  /api/history?limit=20
GET  /api/history/{id}
```

Interactive API documentation is available at `/docs` while the backend is running.

## Project structure

```text
scamshield-ai/
├── frontend/
│   ├── src/
│   │   ├── App.jsx
│   │   ├── main.jsx
│   │   ├── services/
│   │   └── styles.css
│   ├── Dockerfile
│   ├── nginx.conf
│   └── package.json
├── backend/
│   ├── app/
│   │   ├── agents/
│   │   ├── ai/
│   │   ├── api/
│   │   ├── database/
│   │   ├── models/
│   │   ├── services/
│   │   └── tools/
│   ├── tests/
│   ├── Dockerfile
│   ├── pytest.ini
│   └── requirements.txt
├── docs/
├── docker-compose.yml
├── .env.example
└── README.md
```

## Local setup

### 1. Environment

Copy the environment template:

```bash
cp .env.example .env
```

Windows PowerShell:

```powershell
Copy-Item .env.example .env
```

Default configuration works for deterministic Message and URL analysis without an AI key.

### 2. Backend

```bash
cd backend
python -m venv .venv
```

Windows:

```powershell
.venv\Scripts\Activate.ps1
```

macOS/Linux:

```bash
source .venv/bin/activate
```

Install and run:

```bash
pip install -r requirements.txt
uvicorn app.main:app --reload
```

Backend:

```text
http://localhost:8000
```

### 3. Frontend

In another terminal:

```bash
cd frontend
npm install
npm run dev
```

Frontend:

```text
http://localhost:5173
```


## One-command demo start

Windows PowerShell:

```powershell
.\start-demo.ps1
```

macOS/Linux:

```bash
./start-demo.sh
```

These scripts create `.env` from `.env.example` when needed and start the Docker Compose stack.

## AI configuration

AI is optional for core Message and URL analysis. Screenshot text extraction requires a supported multimodal provider.

### Gemini

```env
AI_PROVIDER=gemini
AI_API_KEY=your_key_here
AI_MODEL=gemini-2.5-flash
AI_BASE_URL=
AI_TIMEOUT_SECONDS=15
```

### OpenAI-compatible

```env
AI_PROVIDER=openai
AI_API_KEY=your_key_here
AI_MODEL=your_model_name
AI_BASE_URL=
AI_TIMEOUT_SECONDS=15
```

Never commit real API keys.

## Other environment variables

```env
DATABASE_URL=sqlite:///./scamshield.db
SCREENSHOT_MAX_BYTES=5242880
CORS_ORIGINS=http://localhost:5173,http://localhost:8080
```

Frontend environment:

```env
VITE_API_BASE_URL=http://localhost:8000
```

## Screenshot security

Screenshot uploads are limited by file type, file signature, and size.

Accepted formats:

- PNG
- JPG/JPEG
- WEBP

Raw image bytes are not stored in SQLite history. ScamShield stores a sanitized preview of extracted text and the sanitized analysis report.

## URL security

ScamShield does not visit user-submitted URLs. It analyzes URL text and structure locally, including signals such as:

- HTTPS presence
- IP-address hosts
- suspicious keywords
- unusual URL structure
- excessive subdomains
- URL shorteners
- brand/domain mismatch patterns

These signals do not prove maliciousness. They contribute to the application risk assessment.

## History privacy

History stores sanitized previews instead of unnecessary full raw input.

Message previews redact common credential-like patterns. URL history strips query strings, fragments, and embedded user information before persistence.

## Tests

Install development requirements:

```bash
cd backend
pip install -r requirements-dev.txt
pytest -q
```

Verified final backend result:

```text
47 passed
```

Coverage includes:

- Message analysis
- URL analysis
- Screenshot analysis
- Structured AI validation
- AI fallback
- History persistence
- Privacy redaction
- Database migration
- Invalid upload handling
- Four hackathon scam demo cases
- Legitimate low-risk control case
- 10-case scam release corpus
- 5-case legitimate release corpus
- 5 API edge cases

## Docker deployment

Create `.env` first, then run:

```bash
docker compose up --build
```

Open:

```text
Frontend: http://localhost:8080
Backend:  http://localhost:8000
API docs: http://localhost:8000/docs
```

The Compose setup uses a persistent volume for SQLite data.

The Docker Compose frontend uses same-origin `/api` requests through Nginx. For separately hosted frontend and backend services, set `VITE_API_BASE_URL` to the public backend URL and set `CORS_ORIGINS` to the public frontend origin.

## Release verification

Run the complete backend suite:

```bash
cd backend
pytest -q
```

Run the deterministic release smoke check:

```bash
python scripts/release_check.py
```

After configuring a real Gemini or OpenAI-compatible key, verify the live provider:

```bash
python scripts/verify_live_ai.py
```

No real API credentials are included in this repository.

Final operational documents:

- `docs/PHASE_8.md`
- `docs/ARCHITECTURE.md`
- `docs/FINAL_DEMO_SCRIPT.md`
- `docs/SUBMISSION_CHECKLIST.md`
- `docs/DEPLOYMENT.md`
- `docs/FINAL_CHECKLIST.md`
- `docs/JUDGE_QA.md`

## Limitations

- Risk scores are heuristic application scores, not calibrated probabilities.
- ScamShield cannot guarantee content is malicious or safe.
- URL analysis does not perform live threat-intelligence lookups.
- Screenshot extraction depends on the configured multimodal AI provider.
- Sophisticated scams with weak textual signals might receive a lower risk score.
- Legitimate messages sometimes contain urgency or payment language, so users should review the evidence instead of relying on the score alone.

## Future roadmap

After the hackathon MVP is stable:

- Optional threat-intelligence integration
- More robust domain reputation signals
- Multi-language analysis
- Accessibility improvements
- Exportable incident report
- Broader test corpus

Authentication, payments, complex RAG, blockchain, custom ML training, and large multi-agent systems are intentionally outside the 2-day MVP scope.

## Demo close

ScamShield does not simply generate an answer. It analyzes the input, selects relevant analysis steps, gathers signals, calculates deterministic risk, explains its findings, and gives actionable safety guidance.

Before You Click, Ask ScamShield.
