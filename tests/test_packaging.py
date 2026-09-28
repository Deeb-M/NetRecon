import unittest
from pathlib import Path


class PackagingTests(unittest.TestCase):
    def test_product_modules_are_included_in_package(self) -> None:
        pyproject = Path("pyproject.toml").read_text(encoding="utf-8")

        required_modules = (
            "evidence_planner",
            "evidence_collector",
            "evidence_action_plan",
            "evidence_gaps",
            "adaptive_investigation",
            "investigation_orchestration",
            "investigation_state",
            "investigation_explanation",
            "investigation_synthesis",
            "investigation_memory",
            "investigation_history",
            "finding_requirements",
            "finding_collection_planner",
            "requirement_collection",
        )

        for module in required_modules:
            with self.subTest(module=module):
                self.assertIn(f'"{module}"', pyproject)


if __name__ == "__main__":
    unittest.main()
