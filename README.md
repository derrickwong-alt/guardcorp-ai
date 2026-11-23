# GuardCorp AI
> **Automated Enterprise-Grade Runtime AI Security Suite for One-Person Companies (OPCs)**

Built for the **QwenWork x Hashmeta AI OPC Hackathon**  
**Track 2: AI Governance, Security & Decision-Making**

---

## 🛡️ Executive Summary
Solo entrepreneurs operating One-Person Companies (OPCs) rely heavily on autonomous AI worker agents to scale operations. However, unmonitored agents expose solo founders to catastrophic security liabilities—including direct prompt injections, indirect RAG document poisoning, and unauthorized data exfiltration—where a single breach can cause $250,000+ in liabilities and business insolvency.

**GuardCorp AI** bridges the gap between raw AI autonomy and enterprise governance by delivering a multi-layer runtime security stack built specifically for single-operator enterprises.

---

## 🛠️ Architecture & Core Modules

GuardCorp AI consists of 4 tightly integrated operational modules:

1. **Pre-Execution RAG Auditor (`rag_auditor.py`)**:
   * Scans incoming vector store retrievals, user prompts, and PDF document context payloads for hidden injection patterns and system prompt extraction attacks before text reaches worker LLMs.
2. **Real-Time Middleware Guardrails (`middleware_guardrails.py`)**:
   * Intercepts active worker agent tool calls and outgoing API requests in real time, preventing destructive system commands (`rm -rf`, unauthorized POST requests) and enforcing human-in-the-loop controls.
3. **Autonomous AI Incident Response (AIR) Copilot (`air_copilot.py`)**:
   * Captures audit logs in an embedded SQLite database (`guardcorp.db`) and automatically executes containment actions (e.g., container freezing `docker pause` and API key revocation) upon detecting HIGH/CRITICAL threats.
4. **Multi-Tier LLM Routing Engine (`router_engine.py`)**:
   * Optimizes cost, speed, and safety across 3 distinct model tiers:
     * **Tier 1 (Low-Latency Proxy)**: Mistral 7B / Nemo for tool routing & fast sub-100ms dispatch.
     * **Tier 2 (Security & RAG Auditor)**: Qwen 2.5 14B for deep RAG security audits and policy checks.
     * **Tier 3 (Out-Of-Band Threat Sweeper)**: GLM-5.3-Flash / DeepSeek-V4-Flash for background forensic sweeps.

---

## 📁 Repository File Structure

```
guardcorp-ai/
├── guardcorp_enterprise_suite.py  # Master orchestration engine
├── rag_auditor.py                  # Pre-Execution RAG Auditor module
├── middleware_guardrails.py       # Real-time tool call guardrails
├── air_copilot.py                  # Autonomous AI Incident Response copilot
├── router_engine.py                # Multi-tier LLM routing topology engine
├── rules_config.json               # Hot-reloadable security configuration
├── guardcorp_demo_telemetry.json  # Pre-formatted telemetry payload for Hashmeta AI UI
├── requirements.txt                # Python package dependencies
└── README.md                       # Complete documentation
```

---

## 🚀 Quick Start & Usage

### 1. Test Run
To run the full end-to-end security suite:

```bash
python3 guardcorp_enterprise_suite.py
```

### 2. Sample Code Integration

```python
from guardcorp_enterprise_suite import GuardCorpEnterpriseSuite

# Initialize Suite
suite = GuardCorpEnterpriseSuite()

# Process Agent Request
result = suite.process_agent_request(
    agent_id="WorkerAgent_01",
    input_payload="Generate Q4 financial summary.",
    proposed_tool_call={"name": "fetch_data", "args": {"source": "db"}}
)

print(f"Execution Status: {result['overall_status']}")
```

---

## 📊 Compliance & Governance Alignment
* **NIST AI RMF 1.0**: Maps directly to GOVERN 1.1, MAP 1.2, MEASURE 2.1, and MANAGE 2.3 functions.
* **OWASP Top 10 for LLMs**: Provides runtime mitigation against **LLM01 (Prompt Injection)**, **LLM02 (Sensitive Information Disclosure)**, and **LLM08 (Excessive Agency)**.

---

*Developed by Figtree GuardCorp Technologies for the QwenWork x Hashmeta AI OPC Hackathon.*
