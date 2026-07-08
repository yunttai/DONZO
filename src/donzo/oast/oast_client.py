from __future__ import annotations

from dataclasses import dataclass, field
from typing import Protocol

from donzo.models import stable_id


class OASTClient(Protocol):
    def allocate_token(
        self, *, fuzz_id: str, endpoint_id: str, parameter: str
    ) -> dict[str, str]: ...

    def interactions(self, token: str) -> list[dict[str, object]]: ...


@dataclass
class InMemoryOASTClient:
    base_domain: str = "oast.invalid"
    stored_interactions: list[dict[str, object]] = field(default_factory=list)

    def allocate_token(self, *, fuzz_id: str, endpoint_id: str, parameter: str) -> dict[str, str]:
        token = stable_id("oast_token", fuzz_id, endpoint_id, parameter)
        return {
            "token": token,
            "url": f"https://{token}.{self.base_domain}/",
            "fuzz_id": fuzz_id,
            "endpoint_id": endpoint_id,
            "parameter": parameter,
        }

    def interactions(self, token: str) -> list[dict[str, object]]:
        return [item for item in self.stored_interactions if item.get("token") == token]
