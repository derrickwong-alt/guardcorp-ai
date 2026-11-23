import logging
from typing import Dict, Any

logging.basicConfig(level=logging.INFO, format="%(asctime)s - [LLMRouter] - %(levelname)s - %(message)s")

class LLMRouterEngine:
    """
    Multi-Tier LLM Routing Topology.
    Routes tasks across model tiers based on speed, reasoning depth, and security requirements:
      - Tier 1 (Low-Latency Proxy): Mistral 7B / Nemo (Fast tool dispatch, sub-100ms routing)
      - Tier 2 (Security & RAG Auditor): Qwen 2.5 14B (Deep payload verification, policy checks)
      - Tier 3 (Out-Of-Band Sweeper): GLM-5.3-Flash / DeepSeek-V4-Flash (Async audit sweeps, forensic analysis)
    """

    MODEL_TIERS = {
        "tier_1_proxy": {"name": "Mistral-7B-Instruct / Nemo", "target_latency_ms": 80, "purpose": "Fast tool routing & prompt proxy"},
        "tier_2_auditor": {"name": "Qwen-2.5-14B-Instruct", "target_latency_ms": 320, "purpose": "Deep RAG payload auditing & policy enforcement"},
        "tier_3_sweeper": {"name": "GLM-5.3-Flash / DeepSeek-V4-Flash", "target_latency_ms": 1200, "purpose": "Out-of-band threat sweeps & forensic analysis"}
    }

    def route_request(self, task_type: str, priority: str = "normal") -> Dict[str, Any]:
        """
        Determines the optimal LLM tier for a given operational task.
        """
        if task_type in ["tool_routing", "quick_query", "proxy"]:
            tier_key = "tier_1_proxy"
        elif task_type in ["rag_audit", "policy_check", "guardrail_scan"]:
            tier_key = "tier_2_auditor"
        elif task_type in ["forensic_sweep", "out_of_band_audit", "log_analysis"]:
            tier_key = "tier_3_sweeper"
        else:
            tier_key = "tier_2_auditor"

        selected_tier = self.MODEL_TIERS[tier_key]
        logging.info(f"Task '{task_type}' routed to Model Tier: {selected_tier['name']}")
        
        return {
            "task_type": task_type,
            "selected_model": selected_tier["name"],
            "purpose": selected_tier["purpose"],
            "estimated_latency_ms": selected_tier["target_latency_ms"]
        }

if __name__ == "__main__":
    router = LLMRouterEngine()
    print(router.route_request("rag_audit"))
    print(router.route_request("tool_routing"))
    print(router.route_request("forensic_sweep"))
