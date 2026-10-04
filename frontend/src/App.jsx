import { useEffect, useMemo, useState } from "react";
import {
  AlertTriangle,
  CheckCircle2,
  Clock3,
  FileImage,
  History,
  ImageUp,
  Info,
  Link2,
  LoaderCircle,
  MessageSquareText,
  RefreshCw,
  ScanSearch,
  Server,
  ShieldCheck,
  UploadCloud,
} from "lucide-react";

import {
  analyzeMessage,
  analyzeScreenshot,
  analyzeUrl,
  getHealth,
  getHistory,
  getHistoryItem,
} from "./services/api";

// ============================================================
// DEMO DATA
// ============================================================

const messageSamples = [
  {
    label: "Fake bank",
    category: "Phishing",
    text:
      "URGENT: Your bank account has been suspended. " +
      "Verify your password and OTP immediately using " +
      "https://example.com/login",
  },
  {
    label: "Prize scam",
    category: "Prize/Lottery Scam",
    text:
      "Congratulations! You've won $5,000. " +
      "Pay a $20 processing fee to claim your prize.",
  },
  {
    label: "Job scam",
    category: "Job Scam",
    text:
      "Earn $500 per day working from home. " +
      "Pay a $30 registration fee to start.",
  },
  {
    label: "Investment",
    category: "Investment Scam",
    text: "Guaranteed 300% return in 7 days. " + "No risk. Deposit $500 today.",
  },
  {
    label: "OTP paraphrase",
    category: "Credential Theft",
    text:
      "Tell me the six-digit security code that was " +
      "just sent to your phone.",
  },
  {
    label: "Security advice",
    category: "Low-risk control",
    text: "Never share your OTP or password with anyone.",
  },
  {
    label: "Legitimate",
    category: "Low-risk control",
    text:
      "Hi, our study group meets in the library at " +
      "3 PM tomorrow. Bring your notes if you have them.",
  },
];

const urlSamples = [
  {
    label: "Normal URL",
    text: "https://example.com/about",
  },
  {
    label: "IP login",
    text: "http://192.0.2.10/login/verify-account",
  },
  {
    label: "Brand mismatch",
    text: "https://paypal.security-check.example.com/login",
  },
  {
    label: "Shortened link",
    text: "https://bit.ly/account-verify",
  },
];

// ============================================================
// PROGRESS
// ============================================================

const progressStages = {
  message: [
    "Inspecting message content",
    "Running deterministic rules and trained ML",
    "Normalizing V2 taxonomy evidence",
    "Fusing evidence and calculating risk",
    "Generating safety automation",
  ],

  url: [
    "Parsing URL structure",
    "Checking suspicious URL signals",
    "Normalizing URL taxonomy evidence",
    "Calculating deterministic risk",
    "Generating safety recommendations",
  ],

  screenshot: [
    "Validating screenshot",
    "Extracting visible text",
    "Running message analysis pipeline",
    "Fusing evidence and calculating risk",
    "Generating safety recommendations",
  ],
};

// ============================================================
// HELPERS
// ============================================================

function riskClass(level) {
  return `risk-${(level || "low").toLowerCase()}`;
}

function formatDate(value) {
  if (!value) return "";

  return new Intl.DateTimeFormat(undefined, {
    dateStyle: "medium",
    timeStyle: "short",
  }).format(new Date(value));
}

function inputTypeLabel(type) {
  if (type === "url") {
    return "URL";
  }

  if (type === "screenshot") {
    return "screenshot";
  }

  return "message";
}

function InputTypeIcon({ type, size = 14 }) {
  if (type === "url") {
    return <Link2 size={size} />;
  }

  if (type === "screenshot") {
    return <FileImage size={size} />;
  }

  return <MessageSquareText size={size} />;
}

// ============================================================
// LOADING PROGRESS
// ============================================================

function LoadingProgress({ inputType, stageIndex }) {
  const stages = progressStages[inputType] || progressStages.message;

  return (
    <div className="analysis-progress">
      <LoaderCircle className="spin" size={38} />

      <h2>
        {stages[Math.min(stageIndex, stages.length - 1)]}
        ...
      </h2>

      <div className="progress-stage-list" aria-live="polite">
        {stages.map((stage, index) => (
          <div
            className={`progress-stage ${
              index < stageIndex ? "done" : index === stageIndex ? "active" : ""
            }`}
            key={stage}
          >
            <span>{index < stageIndex ? "✓" : index + 1}</span>

            <p>{stage}</p>
          </div>
        ))}
      </div>

      <small>
        These stages represent ScamShield&apos;s bounded analysis pipeline.
        External verification is not claimed.
      </small>
    </div>
  );
}

// ============================================================
// TRAINED ML PANEL
// ============================================================

function MLEvidencePanel({ result }) {
  if (!result) {
    return null;
  }

  const score =
    typeof result.ml_scam_score === "number"
      ? `${(result.ml_scam_score * 100).toFixed(1)}%`
      : "Unavailable";

  const threshold =
    typeof result.ml_selected_threshold === "number"
      ? result.ml_selected_threshold.toFixed(2)
      : "Unavailable";

  return (
    <div className="v2-card">
      <div className="v2-card-heading">
        <div>
          <p className="eyebrow">TRAINED ML EVIDENCE</p>

          <h3>Local scam classifier</h3>
        </div>

        <span
          className={`status-pill ${
            result.ml_status === "used" ? "status-success" : "status-muted"
          }`}
        >
          {result.ml_status || "disabled"}
        </span>
      </div>

      <div className="evidence-metrics">
        <div>
          <span>Prediction</span>

          <strong>{result.ml_predicted_label || "Unavailable"}</strong>
        </div>

        <div>
          <span>Model score</span>

          <strong>{score}</strong>
        </div>

        <div>
          <span>Frozen threshold</span>

          <strong>{threshold}</strong>
        </div>

        <div>
          <span>Model version</span>

          <strong>{result.ml_model_version || "Unavailable"}</strong>
        </div>
      </div>

      <small className="panel-note">
        The ML score is supporting evidence. It is not ScamShield&apos;s final
        0–100 risk score.
      </small>
    </div>
  );
}

// ============================================================
// EVIDENCE FUSION PANEL
// ============================================================

function EvidenceFusionPanel({ result }) {
  if (!result) {
    return null;
  }

  const normalized = result.normalized_indicators || [];

  const mitigations = result.mitigating_indicators || [];

  const sources = result.evidence_sources || [];

  const adjustments = result.risk_adjustments || [];

  const hasEvidence =
    normalized.length > 0 ||
    mitigations.length > 0 ||
    sources.length > 0 ||
    adjustments.length > 0;

  if (!hasEvidence) {
    return null;
  }

  return (
    <div className="v2-card">
      <div className="v2-card-heading">
        <div>
          <p className="eyebrow">V2 EVIDENCE FUSION</p>

          <h3>Taxonomy-normalized evidence</h3>
        </div>

        {result.taxonomy_version && (
          <span className="taxonomy-version">
            Taxonomy v{result.taxonomy_version}
          </span>
        )}
      </div>

      {sources.length > 0 && (
        <div className="chip-section">
          <span>Evidence sources</span>

          <div className="chip-list">
            {sources.map((source) => (
              <span className="evidence-chip" key={source}>
                {source.replaceAll("-", " ")}
              </span>
            ))}
          </div>
        </div>
      )}

      {normalized.length > 0 && (
        <div className="chip-section">
          <span>Normalized scam indicators</span>

          <div className="chip-list">
            {normalized.map((indicator) => (
              <span className={"evidence-chip positive-chip"} key={indicator}>
                {indicator.replaceAll("_", " ")}
              </span>
            ))}
          </div>
        </div>
      )}

      {mitigations.length > 0 && (
        <div className="chip-section">
          <span>Mitigating indicators</span>

          <div className="chip-list">
            {mitigations.map((indicator) => (
              <span className={"evidence-chip mitigation-chip"} key={indicator}>
                {indicator.replaceAll("_", " ")}
              </span>
            ))}
          </div>
        </div>
      )}

      {adjustments.length > 0 && (
        <div className="risk-adjustments">
          <span>Risk-engine explanation</span>

          <ul>
            {adjustments.map((item, index) => (
              <li key={`${index}-${item}`}>{item}</li>
            ))}
          </ul>
        </div>
      )}
    </div>
  );
}

// ============================================================
// REAL AGENT TRACE
// ============================================================

function AgentTracePanel({ trace = [] }) {
  if (!trace.length) {
    return null;
  }

  return (
    <div className="v2-card">
      <div className="v2-card-heading">
        <div>
          <p className="eyebrow">REAL AGENT TRACE</p>

          <h3>Backend execution path</h3>
        </div>

        <span className="status-pill status-success">{trace.length} steps</span>
      </div>

      <div className="agent-trace-list">
        {trace.map((step, index) => (
          <div className="agent-trace-item" key={`${step.agent}-${index}`}>
            <div className="agent-number">{index + 1}</div>

            <div className="agent-trace-content">
              <div className="agent-trace-title">
                <strong>{step.agent}</strong>

                <span
                  className={`agent-status agent-${step.status || "disabled"}`}
                >
                  {step.status || "disabled"}
                </span>
              </div>

              <p>{step.summary}</p>
            </div>
          </div>
        ))}
      </div>

      <small className="panel-note">
        This trace is returned by the backend from agents that actually executed
        during the request.
      </small>
    </div>
  );
}

// ============================================================
// INCIDENT AUTOMATION PANEL
// ============================================================

function IncidentReportPanel({ report }) {
  if (!report) {
    return null;
  }

  return (
    <div
      className={`incident-card incident-${(
        report.risk_level || "high"
      ).toLowerCase()}`}
    >
      <div className="incident-heading">
        <AlertTriangle size={26} />

        <div>
          <p className="eyebrow">INCIDENT AUTOMATION</p>

          <h3>{report.title}</h3>
        </div>

        <span className={`incident-priority ${riskClass(report.risk_level)}`}>
          {report.priority}
        </span>
      </div>

      <p className="incident-summary">{report.summary}</p>

      <div className="incident-meta">
        <div>
          <span>Category</span>

          <strong>{report.category}</strong>
        </div>

        <div>
          <span>Risk</span>

          <strong>{report.risk_score}/100</strong>
        </div>
      </div>

      {report.evidence?.length > 0 && (
        <div className="chip-section">
          <span>Escalation evidence</span>

          <div className="chip-list">
            {report.evidence.map((item) => (
              <span className={"evidence-chip positive-chip"} key={item}>
                {item.replaceAll("_", " ")}
              </span>
            ))}
          </div>
        </div>
      )}

      <div className="incident-reason">
        <strong>Why escalation triggered</strong>

        <p>{report.escalation_reason}</p>
      </div>

      {report.recommended_actions?.length > 0 && (
        <div className="incident-actions">
          <strong>Immediate actions</strong>

          <ul>
            {report.recommended_actions.map((action) => (
              <li key={action}>{action}</li>
            ))}
          </ul>
        </div>
      )}
    </div>
  );
}

// ============================================================
// RESULT PANEL
// ============================================================

function ResultPanel({ result, loading, inputType, stageIndex = 0 }) {
  if (!result && !loading) {
    return (
      <div className="empty-state">
        <ShieldCheck size={44} />

        <h2>Risk report</h2>

        <p>
          Your explainable {inputTypeLabel(inputType)} assessment will appear
          here.
        </p>
      </div>
    );
  }

  if (loading) {
    return <LoadingProgress inputType={inputType} stageIndex={stageIndex} />;
  }

  return (
    <div className="report">
      {/* ==================================================
          RISK HEADER
          ================================================== */}

      <div className="report-top">
        <div>
          <p className="eyebrow">RISK ASSESSMENT</p>

          <h2 className={riskClass(result.risk_level)}>
            {result.risk_level} RISK
          </h2>

          {result.analysis_id && (
            <small className="analysis-id">
              Analysis #{result.analysis_id}
            </small>
          )}
        </div>

        <div className={`score-circle ${riskClass(result.risk_level)}`}>
          <strong>{result.risk_score}</strong>

          <span>/100</span>
        </div>
      </div>

      {/* ==================================================
          CATEGORY
          ================================================== */}

      <div className="category-box">
        <span>Likely category</span>

        <strong>{result.category}</strong>

        {result.secondary_categories?.length > 0 && (
          <small>Also: {result.secondary_categories.join(", ")}</small>
        )}
      </div>

      {/* ==================================================
          URL METADATA
          ================================================== */}

      {inputType === "url" && (
        <div className="url-meta">
          <div>
            <span>Host</span>

            <strong>{result.host}</strong>
          </div>

          <div>
            <span>HTTPS</span>

            <strong>{result.uses_https ? "Yes" : "No"}</strong>
          </div>
        </div>
      )}

      {/* ==================================================
          SCREENSHOT METADATA
          ================================================== */}

      {inputType === "screenshot" && (
        <div className="screenshot-meta">
          <div>
            <span>File</span>

            <strong>{result.file_name}</strong>
          </div>

          <div>
            <span>Text extraction</span>

            <strong>{result.text_extraction_provider}</strong>
          </div>

          <div className="extracted-text-card">
            <span>Extracted text</span>

            <p>{result.extracted_text}</p>
          </div>
        </div>
      )}

      {/* ==================================================
          AI STATUS
          ================================================== */}

      <div className="ai-status-row">
        <span className={`ai-status ai-${result.ai_status || "disabled"}`}>
          AI:{" "}
          {result.ai_status === "used"
            ? `Used${result.ai_provider ? ` (${result.ai_provider})` : ""}`
            : result.ai_status === "fallback"
              ? "Fallback"
              : "Disabled"}
        </span>

        <span className="score-note">Final risk score stays deterministic</span>
      </div>

      {/* ==================================================
          SUMMARY
          ================================================== */}

      <p className="summary">{result.summary}</p>

      {/* ==================================================
          V2 PANELS
          ================================================== */}

      <MLEvidencePanel result={result} />

      <EvidenceFusionPanel result={result} />

      <AgentTracePanel trace={result.agent_trace || []} />

      <IncidentReportPanel report={result.incident_report} />

      {/* ==================================================
          DETERMINISTIC INDICATORS
          ================================================== */}

      <div>
        <h3>Deterministic indicators</h3>

        <div className="indicator-list">
          {result.indicators.length === 0 ? (
            <div className="indicator safe">
              <CheckCircle2 size={18} />
              No strong indicators detected
            </div>
          ) : (
            result.indicators.map((indicator) => (
              <div className="indicator" key={indicator.code}>
                <AlertTriangle size={18} />

                <div>
                  <strong>
                    {indicator.name} <span>+{indicator.weight}</span>
                  </strong>

                  <p>{indicator.description}</p>
                </div>
              </div>
            ))
          )}
        </div>
      </div>

      {/* ==================================================
          AI OBSERVATIONS
          ================================================== */}

      {result.ai_observations?.length > 0 && (
        <div className="ai-observation-box">
          <h3>AI observations</h3>

          <div className="indicator-list">
            {result.ai_observations.map((observation) => (
              <div
                className={"indicator ai-indicator"}
                key={`${observation.name}-${observation.description}`}
              >
                <ShieldCheck size={18} />

                <div>
                  <strong>
                    {observation.name} <span>{observation.severity}</span>
                  </strong>

                  <p>{observation.description}</p>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* ==================================================
          ANALYSIS PIPELINE
          ================================================== */}

      {result.analysis_steps?.length > 0 && (
        <div className="analysis-steps">
          <h3>Analysis pipeline</h3>

          <ol>
            {result.analysis_steps.map((step, index) => (
              <li key={`${index}-${step}`}>{step}</li>
            ))}
          </ol>
        </div>
      )}

      {/* ==================================================
          SAFETY ADVICE
          ================================================== */}

      <div className="advice-box">
        <h3>Recommended action</h3>

        <ul>
          {result.recommended_actions.map((action) => (
            <li key={action}>{action}</li>
          ))}
        </ul>
      </div>

      <p className="disclaimer">{result.disclaimer}</p>
    </div>
  );
}

// ============================================================
// HISTORY
// ============================================================

function HistoryView({
  items,
  loading,
  error,
  selected,
  detailLoading,
  onRefresh,
  onSelect,
}) {
  return (
    <section className="history-page">
      <div className="history-heading">
        <div>
          <p className="eyebrow">ANALYSIS HISTORY</p>

          <h1>Recent assessments.</h1>

          <p className="lead">
            ScamShield stores sanitized previews and analysis results for the
            local hackathon demo.
          </p>
        </div>

        <button
          className="secondary-button"
          type="button"
          onClick={onRefresh}
          disabled={loading}
        >
          <RefreshCw className={loading ? "spin" : ""} size={17} />
          Refresh
        </button>
      </div>

      {error && <div className="error-box history-error">{error}</div>}

      <div className="history-grid">
        <div className="history-list-card">
          {loading && items.length === 0 ? (
            <div className="history-loading">
              <LoaderCircle className="spin" size={28} />
              Loading history...
            </div>
          ) : items.length === 0 ? (
            <div className="history-empty">
              <History size={34} />

              <h2>No analyses yet</h2>

              <p>Run a scanner and it will appear here.</p>
            </div>
          ) : (
            items.map((item) => (
              <button
                className={`history-item ${
                  selected?.id === item.id ? "selected" : ""
                }`}
                type="button"
                key={item.id}
                onClick={() => onSelect(item.id)}
              >
                <div className="history-item-top">
                  <span className="history-type">
                    <InputTypeIcon type={item.input_type} />

                    {item.input_type}
                  </span>

                  <span
                    className={`history-score ${riskClass(item.risk_level)}`}
                  >
                    {item.risk_score}
                    /100
                  </span>
                </div>

                <strong>{item.scam_category}</strong>

                <p>{item.input_content}</p>

                <small>
                  <Clock3 size={12} />

                  {formatDate(item.created_at)}
                </small>
              </button>
            ))
          )}
        </div>

        <section className="result-card history-result-card">
          {detailLoading ? (
            <ResultPanel
              result={null}
              loading
              inputType={selected?.input_type || "message"}
            />
          ) : selected ? (
            <>
              <div className="stored-preview">
                <span>Stored preview</span>

                <p>{selected.input_content}</p>
              </div>

              <ResultPanel
                result={selected.result}
                loading={false}
                inputType={selected.input_type}
              />
            </>
          ) : (
            <div className="empty-state">
              <History size={44} />

              <h2>Select an assessment</h2>

              <p>Open a history item to review its risk report.</p>
            </div>
          )}
        </section>
      </div>
    </section>
  );
}

// ============================================================
// ABOUT
// ============================================================

function AboutView() {
  const flow = [
    "Orchestrator / Router",
    "Message / URL / Vision Agent",
    "Rules + Trained ML + Semantic AI",
    "Evidence Fusion Agent",
    "V2 Indicator Taxonomy",
    "Deterministic Risk Agent",
    "Safety / Automation Agent",
    "Explainable Final Report",
  ];

  return (
    <section className="about-page">
      <p className="eyebrow">HOW SCAMSHIELD V2 WORKS</p>

      <h1>Multi-agent scam analysis with explainable scoring.</h1>

      <p className="lead">
        ScamShield V2 combines deterministic rules, a trained local text
        classifier, semantic AI, taxonomy normalization, evidence fusion, and
        bounded specialized agents. The final 0–100 risk score remains
        controlled by deterministic application logic.
      </p>

      <div className="about-grid">
        <div className="about-card">
          <h2>Agent workflow</h2>

          <div className="architecture-flow">
            {flow.map((item, index) => (
              <div key={item} className="architecture-item">
                <span>{index + 1}</span>

                <strong>{item}</strong>
              </div>
            ))}
          </div>
        </div>

        <div className="about-card">
          <h2>Safety position</h2>

          <div className="principle-list">
            <p>
              <CheckCircle2 size={18} />
              Reports suspicious indicators instead of claiming certainty.
            </p>

            <p>
              <CheckCircle2 size={18} />
              Keeps deterministic application logic authoritative for the final
              risk score.
            </p>

            <p>
              <CheckCircle2 size={18} />
              Uses trained ML as supporting evidence rather than a direct fraud
              probability.
            </p>

            <p>
              <CheckCircle2 size={18} />
              Normalizes semantic variations into a stable scam-indicator
              taxonomy.
            </p>

            <p>
              <CheckCircle2 size={18} />
              Uses mitigating indicators to reduce false positives in security
              advice.
            </p>

            <p>
              <CheckCircle2 size={18} />
              Does not visit user-submitted URLs.
            </p>

            <p>
              <CheckCircle2 size={18} />
              Stores sanitized history previews instead of unnecessary raw
              input.
            </p>

            <p>
              <CheckCircle2 size={18} />
              Falls back safely when semantic AI is unavailable.
            </p>
          </div>
        </div>
      </div>

      <div className="judge-card">
        <ShieldCheck size={26} />

        <div>
          <span>Judge-facing differentiator</span>

          <strong>
            ScamShield routes each request through specialized agents, combines
            deterministic rules, trained ML, semantic AI and taxonomy evidence,
            explains the execution path, and generates structured incident
            guidance for high-risk cases.
          </strong>
        </div>
      </div>
    </section>
  );
}

// ============================================================
// APP
// ============================================================

function App() {
  const [page, setPage] = useState("scanner");

  const [activeTab, setActiveTab] = useState("message");

  const [message, setMessage] = useState(messageSamples[0].text);

  const [url, setUrl] = useState(urlSamples[0].text);

  const [screenshot, setScreenshot] = useState(null);

  const [result, setResult] = useState(null);

  const [loading, setLoading] = useState(false);

  const [stageIndex, setStageIndex] = useState(0);

  const [error, setError] = useState("");

  const [health, setHealth] = useState(null);

  const [historyItems, setHistoryItems] = useState([]);

  const [historyLoading, setHistoryLoading] = useState(false);

  const [historyError, setHistoryError] = useState("");

  const [selectedHistory, setSelectedHistory] = useState(null);

  const [detailLoading, setDetailLoading] = useState(false);

  const activeStages = useMemo(
    () => progressStages[activeTab] || progressStages.message,
    [activeTab],
  );

  // =========================================================
  // HEALTH
  // =========================================================

  useEffect(() => {
    getHealth()
      .then(setHealth)
      .catch(() => setHealth(null));
  }, []);

  // =========================================================
  // FAKE-FREE LOADING PROGRESS
  //
  // This is only visual request progress.
  // Real agent execution is shown separately from backend.
  // =========================================================

  useEffect(() => {
    if (!loading) {
      setStageIndex(0);

      return undefined;
    }

    const interval = window.setInterval(() => {
      setStageIndex((current) =>
        Math.min(current + 1, activeStages.length - 1),
      );
    }, 700);

    return () => window.clearInterval(interval);
  }, [loading, activeStages]);

  // =========================================================
  // TAB
  // =========================================================

  function switchTab(tab) {
    setActiveTab(tab);

    setResult(null);

    setError("");
  }

  // =========================================================
  // HISTORY
  // =========================================================

  async function loadHistory() {
    setHistoryLoading(true);

    setHistoryError("");

    try {
      setHistoryItems(await getHistory(30));
    } catch (err) {
      setHistoryError(err.message || "History could not be loaded.");
    } finally {
      setHistoryLoading(false);
    }
  }

  async function openHistory() {
    setPage("history");

    await loadHistory();
  }

  async function selectHistory(id) {
    setDetailLoading(true);

    setHistoryError("");

    try {
      setSelectedHistory(await getHistoryItem(id));
    } catch (err) {
      setHistoryError(err.message || "Analysis record could not be loaded.");
    } finally {
      setDetailLoading(false);
    }
  }

  // =========================================================
  // SCREENSHOT
  // =========================================================

  function chooseScreenshot(file) {
    setError("");

    setResult(null);

    if (!file) {
      setScreenshot(null);

      return;
    }

    const supportedTypes = ["image/png", "image/jpeg", "image/webp"];

    if (!supportedTypes.includes(file.type)) {
      setScreenshot(null);

      setError("Choose a PNG, JPG/JPEG, or WEBP screenshot.");

      return;
    }

    if (file.size > 5 * 1024 * 1024) {
      setScreenshot(null);

      setError("Screenshot must be 5 MB or smaller.");

      return;
    }

    setScreenshot(file);
  }

  // =========================================================
  // ANALYZE
  // =========================================================

  async function handleAnalyze(event) {
    event.preventDefault();

    setError("");

    setResult(null);

    if (activeTab === "message" && !message.trim()) {
      setError("Paste a message before running the analysis.");

      return;
    }

    if (activeTab === "url" && !url.trim()) {
      setError("Enter a URL before running the analysis.");

      return;
    }

    if (activeTab === "screenshot" && !screenshot) {
      setError("Choose a screenshot before running the analysis.");

      return;
    }

    setStageIndex(0);

    setLoading(true);

    try {
      const data =
        activeTab === "message"
          ? await analyzeMessage(message.trim())
          : activeTab === "url"
            ? await analyzeUrl(url.trim())
            : await analyzeScreenshot(screenshot);

      setResult(data);
    } catch (err) {
      setError(err.message || "Unable to complete the analysis.");
    } finally {
      setLoading(false);
    }
  }

  // =========================================================
  // UI
  // =========================================================

  return (
    <main className="app-shell">
      {/* ====================================================
          HEADER
          ==================================================== */}

      <header className="topbar">
        <button
          className="brand-button"
          type="button"
          onClick={() => setPage("scanner")}
        >
          <div className="brand-row compact">
            <div className="brand-icon">
              <ShieldCheck size={25} />
            </div>

            <div>
              <p className="eyebrow">SCAMSHIELD AI V2</p>

              <p className="tagline">Before You Click, Ask ScamShield.</p>
            </div>
          </div>
        </button>

        <div className="header-actions">
          <span
            className={`health-badge ${
              health?.status === "ok" ? "online" : ""
            }`}
          >
            <Server size={13} />

            {health?.status === "ok" ? "API ready" : "API status"}
          </span>

          {health?.ml_ready && (
            <span className="health-badge online">
              <ShieldCheck size={13} />
              ML ready
            </span>
          )}

          <nav className="top-nav" aria-label="Main navigation">
            <button
              type="button"
              className={
                page === "scanner" ? "nav-button active" : "nav-button"
              }
              onClick={() => setPage("scanner")}
            >
              <ScanSearch size={16} />
              Scanner
            </button>

            <button
              type="button"
              className={
                page === "history" ? "nav-button active" : "nav-button"
              }
              onClick={openHistory}
            >
              <History size={16} />
              History
            </button>

            <button
              type="button"
              className={page === "about" ? "nav-button active" : "nav-button"}
              onClick={() => setPage("about")}
            >
              <Info size={16} />
              About
            </button>
          </nav>
        </div>
      </header>

      {/* ====================================================
          PAGE ROUTING
          ==================================================== */}

      {page === "history" ? (
        <HistoryView
          items={historyItems}
          loading={historyLoading}
          error={historyError}
          selected={selectedHistory}
          detailLoading={detailLoading}
          onRefresh={loadHistory}
          onSelect={selectHistory}
        />
      ) : page === "about" ? (
        <AboutView />
      ) : (
        <>
          {/* ========================================
                      HERO
                      ======================================== */}

          <section className="hero-copy">
            <p className="eyebrow">MULTI-AGENT SCAM ANALYZER</p>

            <h1>Check suspicious content before you act.</h1>

            <p className="lead">
              ScamShield V2 combines deterministic rules, trained ML, semantic
              AI, taxonomy-based evidence fusion, and specialized agents to
              produce an explainable risk assessment.
            </p>
          </section>

          {/* ========================================
                      DEMO STRIP
                      ======================================== */}

          <section className="demo-strip" aria-label="Hackathon demo cases">
            <div>
              <span>Demo-ready cases</span>

              <strong>
                Bank phishing · OTP paraphrase · Prize · Job · Investment ·
                Security advice
              </strong>
            </div>

            <small>Use the Message samples below for a fast judge demo.</small>
          </section>

          {/* ========================================
                      TABS
                      ======================================== */}

          <div
            className="scanner-tabs"
            role="tablist"
            aria-label="Scanner type"
          >
            <button
              type="button"
              className={
                activeTab === "message" ? "scanner-tab active" : "scanner-tab"
              }
              onClick={() => switchTab("message")}
            >
              <MessageSquareText size={17} />
              Message
            </button>

            <button
              type="button"
              className={
                activeTab === "url" ? "scanner-tab active" : "scanner-tab"
              }
              onClick={() => switchTab("url")}
            >
              <Link2 size={17} />
              URL
            </button>

            <button
              type="button"
              className={
                activeTab === "screenshot"
                  ? "scanner-tab active"
                  : "scanner-tab"
              }
              onClick={() => switchTab("screenshot")}
            >
              <ImageUp size={17} />
              Screenshot
            </button>
          </div>

          {/* ========================================
                      WORKSPACE
                      ======================================== */}

          <section className="workspace-grid">
            <form className="scanner-card" onSubmit={handleAnalyze}>
              <div className="section-heading">
                <InputTypeIcon type={activeTab} size={22} />

                <div>
                  <h2>
                    {activeTab === "message"
                      ? "Analyze message"
                      : activeTab === "url"
                        ? "Analyze URL"
                        : "Analyze screenshot"}
                  </h2>

                  <p>
                    {activeTab === "message"
                      ? "Paste an SMS, email, WhatsApp " +
                        "message, or social message."
                      : activeTab === "url"
                        ? "Inspect the URL structure " +
                          "without visiting the destination."
                        : "Upload a message screenshot. " +
                          "ScamShield extracts visible text " +
                          "before analysis."}
                  </p>
                </div>
              </div>

              {/* ====================================
                          MESSAGE INPUT
                          ==================================== */}

              {activeTab === "message" && (
                <textarea
                  value={message}
                  onChange={(event) => setMessage(event.target.value)}
                  placeholder={
                    "Paste a suspicious message, " + "email, or chat here..."
                  }
                  maxLength={10000}
                />
              )}

              {/* ====================================
                          URL INPUT
                          ==================================== */}

              {activeTab === "url" && (
                <div className="url-input-wrap">
                  <Link2 size={19} />

                  <input
                    className="url-input"
                    type="text"
                    value={url}
                    onChange={(event) => setUrl(event.target.value)}
                    placeholder={"https://example.com/login"}
                    maxLength={2048}
                    autoCapitalize="none"
                    autoCorrect="off"
                  />
                </div>
              )}

              {/* ====================================
                          SCREENSHOT INPUT
                          ==================================== */}

              {activeTab === "screenshot" && (
                <label className="upload-zone">
                  <input
                    type="file"
                    accept={"image/png," + "image/jpeg," + "image/webp"}
                    onChange={(event) =>
                      chooseScreenshot(event.target.files?.[0] || null)
                    }
                  />

                  <UploadCloud size={34} />

                  <strong>
                    {screenshot ? screenshot.name : "Choose screenshot"}
                  </strong>

                  <span>
                    {screenshot
                      ? `${(screenshot.size / 1024).toFixed(1)} KB`
                      : "PNG, JPG/JPEG or WEBP, " + "up to 5 MB"}
                  </span>

                  <small>
                    Images are processed for visible text. Raw image bytes are
                    not stored in history.
                  </small>
                </label>
              )}

              {/* ====================================
                          SAMPLES
                          ==================================== */}

              {activeTab !== "screenshot" && (
                <div className="sample-section">
                  <span className="sample-label">Try a sample</span>

                  <div className="sample-row">
                    {(activeTab === "message"
                      ? messageSamples
                      : urlSamples
                    ).map((sample) => (
                      <button
                        key={sample.label}
                        type="button"
                        className="sample-chip"
                        title={sample.category || sample.text}
                        onClick={() =>
                          activeTab === "message"
                            ? setMessage(sample.text)
                            : setUrl(sample.text)
                        }
                      >
                        {sample.label}
                      </button>
                    ))}
                  </div>
                </div>
              )}

              {/* ====================================
                          ERROR
                          ==================================== */}

              {error && <div className="error-box">{error}</div>}

              {/* ====================================
                          SUBMIT
                          ==================================== */}

              <button className="primary-button" disabled={loading}>
                {loading ? (
                  <LoaderCircle className="spin" size={19} />
                ) : (
                  <InputTypeIcon type={activeTab} size={19} />
                )}

                {loading
                  ? "Analyzing evidence..."
                  : activeTab === "message"
                    ? "Analyze Message"
                    : activeTab === "url"
                      ? "Analyze URL"
                      : "Analyze Screenshot"}
              </button>
            </form>

            {/* ======================================
                        RESULT
                        ====================================== */}

            <section className="result-card">
              <ResultPanel
                result={result}
                loading={loading}
                inputType={activeTab}
                stageIndex={stageIndex}
              />
            </section>
          </section>
        </>
      )}
    </main>
  );
}

export default App;
