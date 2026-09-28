import re
import unittest
from pathlib import Path


class PackagingTests(unittest.TestCase):
    def test_all_root_product_modules_are_packaged(self) -> None:
        pyproject = Path("pyproject.toml").read_text(encoding="utf-8")
        match = re.search(r"py-modules\s*=\s*\[([\s\S]*?)\]", pyproject)
        self.assertIsNotNone(match)

        packaged_modules = set(re.findall(r'"([^"]+)"', match.group(1)))
        root_modules = {path.stem for path in Path(".").glob("*.py")}

        self.assertEqual(packaged_modules, root_modules)


if __name__ == "__main__":
    unittest.main()
