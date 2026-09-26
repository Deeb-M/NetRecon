import tomllib
import unittest
from pathlib import Path


class PackagingTests(unittest.TestCase):
    def test_evidence_modules_are_included_in_package(self) -> None:
        pyproject = tomllib.loads(
            Path("pyproject.toml").read_text(encoding="utf-8")
        )
        modules = set(pyproject["tool"]["setuptools"]["py-modules"])

        self.assertTrue(
            {"evidence_planner", "evidence_collector"} <= modules
        )


if __name__ == "__main__":
    unittest.main()
