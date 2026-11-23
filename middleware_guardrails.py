import logging
from typing import Dict, Any, List

logging.basicConfig(level=logging.INFO, format="%(asctime)s - [Guardrails] - %(levelname)s - %(message)s")

class MiddlewareGuardrails:
    """
    Real-Time LLM Middleware Guardrails.
    Intercepts active worker agent tool calls, API requests, and outgoing parameters
    to enforce boundary policies and prevent data exfiltration.
    """
    
    FORBIDDEN_COMMANDS = ["rm -rf", "drop table", "chmod 777", "curl -X POST -d", "nc -e", "/etc/passwd"]
    RESTRICTED_APIS = ["payment_gateway_admin", "delete_user_account", "export_all_credentials"]

    def __init__(self, forbidden_commands: List[str] = None):
        self.forbidden_commands = forbidden_commands or self.FORBIDDEN_COMMANDS

    def intercept_tool_call(self, tool_name: str, args: Dict[str, Any]) -> Dict[str, Any]:
        """
        Intercepts tool execution before call dispatch.
        """
        args_str = str(args).lower()
        
        # Check API restrictions
        if tool_name.lower() in self.RESTRICTED_APIS:
            logging.error(f"Guardrail triggered: Tool '{tool_name}' is restricted for autonomous agents!")
            return {
                "action": "REJECTED",
                "reason": f"Tool '{tool_name}' requires manual human-in-the-loop approval.",
                "sanitized_args": None
            }

        # Check command injection in arguments
        for cmd in self.forbidden_commands:
            if cmd in args_str:
                logging.error(f"Guardrail triggered: Forbidden command pattern '{cmd}' detected in args!")
                return {
                    "action": "BLOCKED",
                    "reason": f"Forbidden system command execution attempt detected: '{cmd}'.",
                    "sanitized_args": None
                }

        logging.info(f"Guardrails verified tool call: '{tool_name}' with safe execution bounds.")
        return {
            "action": "ALLOWED",
            "reason": "Passed all safety boundary policies.",
            "sanitized_args": args
        }

if __name__ == "__main__":
    guard = MiddlewareGuardrails()
    res1 = guard.intercept_tool_call("execute_shell", {"cmd": "ls -l && rm -rf /"})
    print("Intercept Result 1:", res1)
    res2 = guard.intercept_tool_call("search_database", {"query": "SELECT * FROM metrics"})
    print("Intercept Result 2:", res2)
