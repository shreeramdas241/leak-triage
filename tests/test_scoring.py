import unittest

from git_finder import (
    classify_rule_id,
    is_test_path,
    redact_secret,
    verdict_from_score,
)


class RedactTests(unittest.TestCase):
    def test_short_secret_fully_masked(self):
        self.assertEqual(redact_secret("abcd"), "****")

    def test_long_secret_keeps_edges(self):
        self.assertEqual(redact_secret("AKIATESTSECRET99"), "AKIA...ET99")


class PathTests(unittest.TestCase):
    def test_src_is_not_test(self):
        self.assertFalse(is_test_path("src/pay.py", ["tests", "spec"]))

    def test_tests_dir_is_test(self):
        self.assertTrue(is_test_path("tests/e2e/login.py", ["tests", "e2e"]))


class ScoreTests(unittest.TestCase):
    def test_rule_rollups(self):
        self.assertEqual(classify_rule_id("aws-access-key"), "AWS_Credentials")
        self.assertEqual(classify_rule_id("github-token"), "API_Keys")
        self.assertEqual(classify_rule_id("generic-secret"), "Generic_Secrets")

    def test_thresholds(self):
        t = {"CRITICAL_THREAT": 80, "HIGH_THREAT": 50, "MEDIUM_THREAT": 25}
        self.assertEqual(verdict_from_score(90, t, False), "CRITICAL_THREAT")
        self.assertEqual(verdict_from_score(55, t, False), "HIGH_THREAT")
        self.assertEqual(verdict_from_score(30, t, False), "MEDIUM_THREAT")
        self.assertEqual(verdict_from_score(5, t, False), "INFORMATIONAL")


if __name__ == "__main__":
    unittest.main()
