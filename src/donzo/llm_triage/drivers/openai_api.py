from __future__ import annotations

from donzo.config import LLMConfig
from donzo.llm_triage.drivers.base import LLMCallError, TribunalDriver
from donzo.llm_triage.schema import EvidencePack, FindingVerdict


class OpenAIDriver(TribunalDriver):
    name = "openai"

    def __init__(self, config: LLMConfig, *, allow_external_llm: bool = False) -> None:
        self.config = config
        self.allow_external_llm = allow_external_llm

    def judge(self, evidence_pack: EvidencePack) -> FindingVerdict:
        raise LLMCallError(
            "openai driver is mandatory by design but not configured in this build. "
            "Wire the API client with schema-constrained responses before enabling final ranking."
        )
