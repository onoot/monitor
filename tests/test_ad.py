"""Regression checks for the ad tool.

Each case asserts a known finding that is present in a local service, plus a
known non-finding that earlier revisions of the rules reported incorrectly.
Run with: python -m tests.test_ad
"""

from __future__ import annotations

import dataclasses
import os
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from ad import sast  # noqa: E402
from ad.config import DEFAULT_EXCLUDED_GLOBS, FlagFormat, load_config  # noqa: E402
from ad.flags import split_envelope, xeger_to_regex  # noqa: E402
from ad.poison import Poisoner, PoisonerMisconfigured  # noqa: E402

SERVICES = ROOT / "services"


def scan(service: str) -> sast.ScanResult:
    return sast.scan([SERVICES / service], DEFAULT_EXCLUDED_GLOBS)


def keys(service: str) -> set[tuple[str, str]]:
    """(rule_id, relative file) pairs found for a service."""
    return {(f.rule_id, f.evidence.file) for f in scan(service).findings}


class FlagshipBugs(unittest.TestCase):
    """Each service has one intended vulnerability that must always surface."""

    def test_magiclib_ignores_password_on_login(self):
        self.assertIn(("AD-AUTH-001", "magicapp/routes.py"), keys("magiclib"))

    def test_curs_builds_sql_with_sprintf(self):
        self.assertIn(("AD-SQL-001", "app/routing.go"), keys("curs"))

    def test_omnyhub_decodes_jwt_without_verifying(self):
        self.assertIn(("AD-JWT-001", "backend/Public/js/utils/chekAuth.js"), keys("Omnyhub"))

    def test_altaycoin_derives_invite_code_from_login(self):
        self.assertIn(
            ("AD-CRYPTO-003", "backend/src/users/users.service.ts"), keys("AltayCoin")
        )


class NoFalsePositives(unittest.TestCase):
    """Safe patterns that earlier revisions mislabelled."""

    def test_bound_parameters_are_not_sql_injection(self):
        # magicapp/sql.py uses cursor.execute("... %s", (value,)) throughout.
        found = keys("magiclib")
        sql_hits = {(rid, f) for rid, f in found if rid == "AD-SQL-001"}
        self.assertEqual(sql_hits, set())

    def test_method_call_update_is_not_sql_keyword(self):
        # `.update(body.password)` must not read as an UPDATE statement.
        for rid, _ in keys("AltayCoin"):
            self.assertNotEqual(rid, "AD-SQL-001")

    def test_registration_reading_a_password_is_not_a_login_bug(self):
        auth = {(rid, f) for rid, f in keys("magiclib") if rid == "AD-AUTH-001"}
        self.assertEqual(auth, {("AD-AUTH-001", "magicapp/routes.py")})


class RuleMetadata(unittest.TestCase):
    def test_every_rule_compiles_and_has_guidance(self):
        for rule in sast.RULES:
            self.assertTrue(rule.title, rule.id)
            self.assertTrue(rule.description, rule.id)
            self.assertTrue(rule.remediation, rule.id)
            self.assertTrue(rule.exploit, rule.id)
            self.assertTrue(rule.breaker, rule.id)
            self.assertTrue(rule.cwe, rule.id)
            self.assertTrue(rule.sources, rule.id)
            self.assertIn(
                rule.severity,
                {"critical", "high", "medium", "low", "info"},
                rule.id,
            )

    def test_rule_ids_are_unique(self):
        ids = [rule.id for rule in sast.RULES]
        self.assertEqual(len(ids), len(set(ids)))

    def test_severity_rank_puts_critical_first(self):
        # Sorting negates the rank, so a larger rank must mean a worse finding.
        self.assertGreater(sast.severity_rank("critical"), sast.severity_rank("high"))
        self.assertGreater(sast.severity_rank("high"), sast.severity_rank("low"))

    def test_critical_findings_sort_first(self):
        for service in ("AltayCoin", "curs", "magiclib", "Omnyhub"):
            severities = [f.severity for f in scan(service).sorted_findings()]
            if "critical" in severities and "low" in severities:
                self.assertLess(severities.index("critical"), severities.index("low"), service)


class Routes(unittest.TestCase):
    def test_flask_methods_are_distinguished(self):
        result = scan("magiclib")
        keys_found = {r.key for r in result.routes}
        self.assertIn("GET /login", keys_found)
        self.assertIn("POST /login", keys_found)

    def test_handler_auth_suppresses_guarded_route(self):
        result = scan("Omnyhub")
        # /users/:id resolves to a handler that checks the Authorization header.
        flagged = {f.evidence.snippet for f in result.findings if f.rule_id == "AD-AUTH-002"}
        self.assertNotIn("ANY /users/:id", flagged)


PATTERN = r"alctf{[a-z0-9_]{16}}"


def build_cfg(pattern: str = PATTERN) -> object:
    """A config with a confirmed flag format, independent of service configs."""
    cfg = load_config(ROOT / "configs" / "magiclib.json")
    return dataclasses.replace(
        cfg,
        flag_format=FlagFormat(pattern=pattern, prefix="alctf{", suffix="}", min_length=16),
        notes="public field that must never be used as a key",
    )


class Flags(unittest.TestCase):
    PATTERN = PATTERN

    def test_xeger_pattern_with_multi_char_class(self):
        regex = xeger_to_regex(self.PATTERN)
        self.assertIsNotNone(regex, "checker-style pattern must be understood")
        self.assertTrue(regex.match("alctf{aaaaaaaaaaaaaaaa}"))
        self.assertFalse(regex.match("alctf{short}"))
        self.assertFalse(regex.match("alctf{aaaaaaaaaaaaaaaaa}"))

    def test_single_range_still_works(self):
        regex = xeger_to_regex(r"alt{[a-z]{4}}")
        self.assertTrue(regex.match("alt{abcd}"))
        self.assertFalse(regex.match("alt{abcde}"))

    def test_split_envelope_keeps_wrapper(self):
        self.assertEqual(split_envelope(self.PATTERN), ("alctf{", "}"))

    def test_embedded_regex_is_refused(self):
        self.assertIsNone(xeger_to_regex(r"flag(?=x)[a-z]"))
        self.assertIsNone(xeger_to_regex(r"flag|[a-z]"))

    def test_literal_mask_stays_consistent_with_pattern(self):
        cfg = build_cfg()
        mask = cfg.flag_format.literal_mask()
        self.assertIsNotNone(mask)
        self.assertTrue(xeger_to_regex(cfg.flag_format.pattern).match(mask))


class Poisoning(unittest.TestCase):
    def make_cfg(self):
        return build_cfg()

    def setUp(self):
        self.cfg = self.make_cfg()
        self.flag = "alctf{aaaaaaaaaaaaaaaa}"

    def test_missing_secret_refuses_to_run(self):
        previous = os.environ.pop("AD_POISON_SECRET", None)
        try:
            with self.assertRaises(PoisonerMisconfigured):
                Poisoner(self.cfg)
        finally:
            if previous is not None:
                os.environ["AD_POISON_SECRET"] = previous

    def test_unknown_actor_is_never_poisoned(self):
        decision = Poisoner(self.cfg, secret=b"k").decision("unknown", "t1", "/", self.flag)
        self.assertEqual(decision.action, "pass_through")
        self.assertIsNone(decision.value)

    def test_checker_is_never_poisoned(self):
        decision = Poisoner(self.cfg, secret=b"k").decision("checker", "t1", "/", self.flag)
        self.assertEqual(decision.action, "pass_through")
        self.assertIsNone(decision.value)

    def test_non_flag_value_is_untouched(self):
        decision = Poisoner(self.cfg, secret=b"k").decision("team", "t1", "/", "hello")
        self.assertEqual(decision.action, "pass_through")

    def test_team_flag_is_poisoned_and_shape_preserved(self):
        poisoner = Poisoner(self.cfg, secret=b"k")
        decision = poisoner.decision("team", "t1", "/api/", self.flag)
        self.assertEqual(decision.action, "poison")
        self.assertEqual(len(decision.value), len(self.flag))
        self.assertTrue(decision.value.startswith("alctf{"))
        self.assertTrue(decision.value.endswith("}"))
        self.assertNotEqual(decision.value, self.flag)
        body = decision.value[len("alctf{") : -1]
        self.assertTrue(all(c.isalnum() or c == "_" for c in body), body)

    def test_poisoning_is_deterministic(self):
        a = Poisoner(self.cfg, secret=b"k").decision("team", "t1", "/api/", self.flag)
        b = Poisoner(self.cfg, secret=b"k").decision("team", "t1", "/api/", self.flag)
        self.assertEqual(a.value, b.value)

    def test_different_teams_and_endpoints_differ(self):
        poisoner = Poisoner(self.cfg, secret=b"k")
        t1 = poisoner.decision("team", "t1", "/api/", self.flag).value
        t2 = poisoner.decision("team", "t2", "/api/", self.flag).value
        other = poisoner.decision("team", "t1", "/other/", self.flag).value
        self.assertNotEqual(t1, t2)
        self.assertNotEqual(t1, other)

    def test_secret_is_not_derived_from_service_notes(self):
        os.environ["AD_POISON_SECRET"] = "from-env"
        try:
            poisoner = Poisoner(self.cfg)
            self.assertEqual(poisoner.secret, b"from-env")
            self.assertNotEqual(poisoner.secret, self.cfg.notes.encode())
        finally:
            os.environ.pop("AD_POISON_SECRET", None)

    def test_disabled_when_pattern_missing(self):
        cfg = dataclasses.replace(self.cfg, flag_format=FlagFormat(pattern=""))
        decision = Poisoner(cfg, secret=b"k").decision("team", "t1", "/", self.flag)
        self.assertEqual(decision.action, "disabled")


if __name__ == "__main__":
    unittest.main(verbosity=2)