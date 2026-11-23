# GuardCorp AI
> Enterprise-Grade Runtime AI Security Suite for One-Person Companies (OPCs)

Built for the **QwenWork x Hashmeta AI OPC Hackathon (Track 2: AI Governance, Security & Decision-Making)**.

## Key Modules
1. **Pre-Execution RAG Auditor**: Scans vector store retrievals and document payloads for hidden prompt injections.
2. **Real-Time Middleware Guardrails**: Intercepts worker agent tool calls and sanitizes inputs against exfiltration.
3. **Autonomous AI Incident Response (AIR) Copilot**: Logs telemetry and executes automated container isolation (`docker pause`) on threat detection.

## Multi-Tier LLM Architecture
* **Low-Latency Proxy**: Mistral 7B / Nemo
* **Deep RAG Security Auditor**: Qwen 2.5 14B
* **Out-Of-Band Threat Sweeper**: GLM-5.3 / DeepSeek-V4-Flash
