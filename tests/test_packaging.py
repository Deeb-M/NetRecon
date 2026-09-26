import unittest
from pathlib import Path


class PackagingTests(unittest.TestCase):
    def test_evidence_modules_are_included_in_package(self) -> None:
        pyproject = Path("pyproject.toml").read_text(encoding="utf-8")

        self.assertIn('"evidence_planner"', pyproject)
        self.assertIn('"evidence_collector"', pyproject)


if __name__ == "__main__":
    unittest.main()
