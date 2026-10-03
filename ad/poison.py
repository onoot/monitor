"""Deterministic flag poisoning.

Hard invariants (AltayCTF 2026 rules):

  * a request classified as `checker` is NEVER modified - a poisoned flag the
    checker cannot read costs the jury points and looks like a service bug
  * a request classified as `unknown` is NEVER modified either; it is treated
    as a team, because mislabelling the checker is far more expensive than
    missing one poisoning opportunity
  * the transform is a pure function of (secret, team, endpoint, flag). The same
    team replaying the same request always receives the same poisoned value, so
    an attacker cannot fingerprint the defence by repeated probing
  * length, character-class profile and flag prefix/suffix are preserved, so
    checkers, schema validators and length assertions keep passing

Poisoning is disabled unless `flag_format.pattern` is configured. There is no
fallback guess.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import re
from dataclasses import dataclass

from .config import Config, FlagFormat
from .flags import split_envelope


class PoisonerMisconfigured(RuntimeError):
    """Raised when poisoning cannot be performed safely."""

# Flag bodies stay inside this alphabet so downstream validators that expect
# [a-z0-9_] keep working.
DEFAULT_ALPHABET = "abcdefghijklmnopqrstuvwxyz0123456789_"


@dataclass(frozen=True)
class PoisonDecision:
    action: str  # "pass_through" | "poison" | "disabled"
    reason: str
    value: str | None = None
    actor: str = "unknown"
    team_key: str = ""

    @property
    def poisoned(self) -> bool:
        return self.action == "poison" and self.value is not None


class Poisoner:
    def __init__(self, cfg: Config, alphabet: str = DEFAULT_ALPHABET, secret: bytes | None = None):
        self.cfg = cfg
        self.fmt: FlagFormat = cfg.flag_format
        self.alphabet = cfg.flag_format.body_alphabet or alphabet
        self.enabled = cfg.flag_format.known
        self.mask = cfg.flag_format.literal_mask()
        self.envelope = split_envelope(cfg.flag_format.pattern) if self.enabled else ("", "")
        # The key must never come from a published field such as notes, otherwise
        # anyone holding a poisoned flag can recompute the scheme.
        resolved = secret or os.environ.get("AD_POISON_SECRET")
        if not resolved:
            raise PoisonerMisconfigured(
                "AD_POISON_SECRET is not set; refusing to derive the poisoning key from "
                "service data. Export a private secret before generating plans."
            )
        self.secret = resolved.encode("utf-8") if isinstance(resolved, str) else resolved

    def decision(self, actor: str, team_key: str, endpoint: str, flag: str) -> PoisonDecision:
        if not self.enabled:
            return PoisonDecision(
                "disabled",
                "flag_format.pattern not configured; poisoning stays off rather than guessing",
                actor=actor,
                team_key=team_key,
            )
        if not flag:
            return PoisonDecision("pass_through", "no flag in payload", actor=actor, team_key=team_key)
        if actor == "checker":
            return PoisonDecision(
                "pass_through", "checker traffic must always receive the exact flag", actor=actor, team_key=team_key
            )
        if actor == "unknown":
            return PoisonDecision(
                "pass_through", "unclassified source; refusing to poison to protect the checker", actor=actor, team_key=team_key
            )
        if not self._is_flag(flag):
            return PoisonDecision("pass_through", "value does not match the configured flag pattern", actor=actor, team_key=team_key)

        poisoned = self._transform(flag, team_key, endpoint)
        return PoisonDecision(
            "poison",
            f"team traffic ({actor}); deterministic per team/endpoint",
            value=poisoned,
            actor=actor,
            team_key=team_key,
        )

    def poison_text(self, blob: str, actor: str, team_key: str, endpoint: str) -> tuple[str, list[PoisonDecision]]:
        """Rewrite every flag-shaped value in a text blob. Returns (text, decisions)."""
        decisions: list[PoisonDecision] = []
        if not self.enabled:
            return blob, [PoisonDecision("disabled", "no flag pattern configured", actor=actor)]

        def replace(match: re.Match[str]) -> str:
            decision = self.decision(actor, team_key, endpoint, match.group(0))
            decisions.append(decision)
            return decision.value or match.group(0)

        return self._flag_regex().sub(replace, blob), decisions

    def _flag_regex(self) -> re.Pattern[str]:
        from .flags import xeger_to_regex

        regex = xeger_to_regex(self.fmt.pattern)
        if regex:
            return regex
        return re.compile(re.escape(self.fmt.pattern))

    def _is_flag(self, flag: str) -> bool:
        return bool(self._flag_regex().match(flag))

    def _transform(self, flag: str, team_key: str, endpoint: str) -> str:
        """Replace the flag body with deterministic, profile-preserving noise."""
        prefix, suffix = self._split(flag)
        body_len = len(flag) - len(prefix) - len(suffix)
        if body_len <= 0:
            return flag
        noise = self._noise(team_key, endpoint, body_len)
        return prefix + noise + suffix

    def _split(self, flag: str) -> tuple[str, str]:
        """Return the (prefix, suffix) that must survive poisoning."""
        mask = self.mask
        if mask and len(mask) == len(flag):
            idxs = [i for i, ch in enumerate(mask) if ch == "_"]
            if idxs:
                return flag[: idxs[0]], flag[idxs[-1] + 1 :]
        prefix, suffix = self.envelope
        if prefix and flag.startswith(prefix):
            if not suffix or flag.endswith(suffix):
                return prefix, suffix
        if self.fmt.prefix and flag.startswith(self.fmt.prefix):
            return self.fmt.prefix, ""
        return "", ""

    def _noise(self, team_key: str, endpoint: str, length: int) -> str:
        seed = f"{team_key}|{endpoint}".encode("utf-8")
        out: list[str] = []
        counter = 0
        while len(out) < length:
            mac = hmac.new(self.secret, seed + counter.to_bytes(4, "big"), hashlib.sha256).digest()
            for byte in mac:
                out.append(self.alphabet[byte % len(self.alphabet)])
                if len(out) >= length:
                    break
            counter += 1
        return "".join(out)

    def describe(self) -> dict:
        return {
            "enabled": self.enabled,
            "flag_pattern": self.fmt.pattern,
            "mask": self.mask,
            "prefix": self.fmt.prefix,
            "envelope": list(self.envelope),
            "alphabet": self.alphabet,
            "checker_policy": "never modify",
            "unknown_policy": "never modify",
            "team_policy": "deterministic per (team, endpoint), length and charset preserved",
            "requires": "flag_format.pattern in the service config",
            "secret_source": "AD_POISON_SECRET",
        }