"""Synthetic unit tests for the conservative language detector."""

import unittest

from src.ethio_cyber_intel.language_detection import (
    MIN_CONFIDENCE,
    detect_article_language,
    detect_language,
)
from tests.fixtures.language_cases import CASES


class LanguageDetectionTests(unittest.TestCase):
    def test_amharic_uses_ethiopic_script(self):
        result = detect_language(CASES["am"])
        self.assertEqual(result.language, "am")
        self.assertEqual(result.method, "ethiopic_script")
        self.assertGreaterEqual(result.confidence, MIN_CONFIDENCE)

    def test_english_detected_from_lexical_evidence(self):
        result = detect_language(CASES["en"])
        self.assertEqual(result.language, "en")
        self.assertEqual(result.method, "lexical_cues_en")
        self.assertGreaterEqual(result.confidence, MIN_CONFIDENCE)

    def test_afaan_oromo_distinguished_from_english(self):
        result = detect_language(CASES["om"])
        self.assertEqual(result.language, "om")
        self.assertEqual(result.method, "lexical_cues_om")
        self.assertGreaterEqual(result.confidence, MIN_CONFIDENCE)

    def test_short_latin_text_returns_unknown(self):
        result = detect_language("security")
        self.assertEqual(result.language, "und")
        self.assertEqual(result.method, "insufficient_text")
        self.assertEqual(result.confidence, 0.0)

    def test_short_ethiopic_script_is_still_identifiable(self):
        result = detect_language("ሰላም")
        self.assertEqual(result.language, "am")
        self.assertEqual(result.method, "ethiopic_script")

    def test_mixed_amharic_and_english_is_mixed(self):
        result = detect_language(CASES["mul"])
        self.assertEqual(result.language, "mul")
        self.assertEqual(result.method, "mixed_script_and_lexical_cues")

    def test_mixed_english_and_afaan_oromo_is_mixed(self):
        result = detect_language(
            "Dhaabbanni tokko odeeffannoo dhuunfaa qorachaa jira. "
            "The organization has reported a data breach to its users."
        )
        self.assertEqual(result.language, "mul")
        self.assertEqual(result.method, "mixed_english_oromo_lexical_cues")

    def test_unsupported_language_returns_unknown(self):
        result = detect_language(CASES["und"])
        self.assertEqual(result.language, "und")
        self.assertLess(result.confidence, MIN_CONFIDENCE)

    def test_conflicting_or_weak_latin_evidence_is_not_forced(self):
        result = detect_language("security update threat")
        self.assertEqual(result.language, "und")
        self.assertLess(result.confidence, MIN_CONFIDENCE)

    def test_article_prefers_full_content(self):
        result = detect_article_language(
            title="የደህንነት ዜና",
            description="የአማርኛ መግለጫ",
            content=CASES["en"],
        )
        self.assertEqual(result.language, "en")


if __name__ == "__main__":
    unittest.main()
