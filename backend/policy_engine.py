import json
import logging
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger("bayora.policy_engine")


@dataclass
class PolicyEvaluationDecision:
    decision: str  # "ALLOW", "BLOCK", "FLAG"
    stage: str     # "INPUT_FILTER" or "OUTPUT_FILTER"
    reasons: List[str] = field(default_factory=list)
    sanitized_text: Optional[str] = None
    policy_version_id: Optional[str] = None
    policy_version_number: Optional[int] = None


class DefensivePolicyEngine:
    """
    Executable defensive checks for Blue Team policies.
    Performs deterministic input validation, pattern matching, synthetic canary detection,
    and output redaction.
    """

    @staticmethod
    def parse_rules(rule_json_str: Optional[str]) -> Dict[str, Any]:
        if not rule_json_str:
            return {}
        try:
            return json.loads(rule_json_str)
        except Exception:
            return {}

    @classmethod
    def evaluate_input(
        cls,
        prompt: str,
        policy_version_id: Optional[str],
        version_number: Optional[int],
        input_rules_str: Optional[str],
    ) -> PolicyEvaluationDecision:
        """
        Evaluates an adversarial input prompt against Blue Team input defenses.
        """
        rules = cls.parse_rules(input_rules_str)
        reasons = []

        # 1. Max input length check
        max_length = rules.get("max_input_length", 4000)
        if len(prompt) > max_length:
            reasons.append(f"INPUT_LENGTH_EXCEEDED: {len(prompt)} > {max_length}")

        # 2. Prohibited regex patterns (prompt injection, jailbreak attempts)
        prohibited_patterns = rules.get("prohibited_patterns", [])
        for pattern in prohibited_patterns:
            try:
                if re.search(pattern, prompt, re.MULTILINE):
                    reasons.append(f"PROHIBITED_INPUT_PATTERN: Matched '{pattern}'")
                    break
            except re.error as e:
                logger.error(f"Invalid regex in policy rule: {pattern} ({e})")

        # 3. Prohibited keywords
        prohibited_keywords = rules.get("prohibited_keywords", [])
        lower_prompt = prompt.lower()
        for kw in prohibited_keywords:
            if kw.lower() in lower_prompt:
                reasons.append(f"PROHIBITED_KEYWORD_DETECTED: '{kw}'")

        if reasons:
            return PolicyEvaluationDecision(
                decision="BLOCK",
                stage="INPUT_FILTER",
                reasons=reasons,
                sanitized_text="[BLOCKED BY BLUE TEAM INPUT DEFENSE POLICY: Request violated adversarial safety constraints]",
                policy_version_id=policy_version_id,
                policy_version_number=version_number,
            )

        return PolicyEvaluationDecision(
            decision="ALLOW",
            stage="INPUT_FILTER",
            reasons=["INPUT_PASSED_ALL_DEFENSES"],
            sanitized_text=prompt,
            policy_version_id=policy_version_id,
            policy_version_number=version_number,
        )

    @classmethod
    def evaluate_output(
        cls,
        raw_output: str,
        policy_version_id: Optional[str],
        version_number: Optional[int],
        output_rules_str: Optional[str],
    ) -> PolicyEvaluationDecision:
        """
        Evaluates model output against Blue Team output defenses (synthetic secret leaks, etc.).
        """
        rules = cls.parse_rules(output_rules_str)
        reasons = []
        sanitized_output = raw_output
        is_blocked = False

        # 1. Max output length
        max_length = rules.get("max_output_length", 8000)
        if len(raw_output) > max_length:
            reasons.append(f"OUTPUT_LENGTH_EXCEEDED: {len(raw_output)} > {max_length}")
            sanitized_output = sanitized_output[:max_length] + "... [TRUNCATED_BY_POLICY]"

        # 2. Synthetic Secret Canary Detection & Scrubbing
        synthetic_secret_patterns = rules.get(
            "synthetic_secret_patterns",
            [
                r"FLAG\{[A-Za-z0-9_-]+\}",
                r"sk-test-[a-zA-Z0-9_-]{16,}",
                r"API_KEY_[A-Z0-9_]{10,}",
                r"SUPER_SECRET_[A-Z0-9_]+",
            ],
        )

        redact_replacement = rules.get(
            "redact_replacement",
            "[BLOCKED: Synthetic secret canary detected and scrubbed by Blue Team Policy]",
        )

        for pattern in synthetic_secret_patterns:
            try:
                if re.search(pattern, raw_output):
                    reasons.append(f"SYNTHETIC_SECRET_CANARY_DETECTED: Matched pattern '{pattern}'")
                    sanitized_output = re.sub(pattern, redact_replacement, sanitized_output)
                    is_blocked = True
            except re.error as e:
                logger.error(f"Invalid regex in output rule: {pattern} ({e})")

        if is_blocked:
            return PolicyEvaluationDecision(
                decision="BLOCK",
                stage="OUTPUT_FILTER",
                reasons=reasons,
                sanitized_text=sanitized_output,
                policy_version_id=policy_version_id,
                policy_version_number=version_number,
            )

        if reasons:
            return PolicyEvaluationDecision(
                decision="FLAG",
                stage="OUTPUT_FILTER",
                reasons=reasons,
                sanitized_text=sanitized_output,
                policy_version_id=policy_version_id,
                policy_version_number=version_number,
            )

        return PolicyEvaluationDecision(
            decision="ALLOW",
            stage="OUTPUT_FILTER",
            reasons=["OUTPUT_PASSED_ALL_DEFENSES"],
            sanitized_text=raw_output,
            policy_version_id=policy_version_id,
            policy_version_number=version_number,
        )
