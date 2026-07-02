"""SCOUT-style LLM tribunal triage layer."""

from donzo.llm_triage.tribunal import run_tribunal, should_triage_with_llm

__all__ = ["run_tribunal", "should_triage_with_llm"]
