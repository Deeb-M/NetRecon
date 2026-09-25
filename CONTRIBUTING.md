# Contributing to NetRecon

Thank you for your interest in contributing to NetRecon.

NetRecon aims to remain conservative, evidence-aware, reproducible, and easy to review. Contributions should preserve those properties.

## Development setup

Clone the repository and create an isolated Python environment:

```bash
git clone https://github.com/Deeb-M/NetRecon.git
cd NetRecon
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e .
```

NetRecon requires Python 3.10 or newer.

## Run the test suite

Before and after making a change, run the complete regression suite:

```bash
python -m unittest discover -s tests -v
```

All tests should pass before a contribution is submitted.

## Contribution principles

- Keep changes focused and as small as reasonably possible.
- Preserve existing CLI and report behavior unless the change intentionally modifies documented behavior.
- Prefer evidence-based analysis over assumptions or speculative findings.
- Normalize input consistently with the existing parser and analysis layers.
- Do not add tests merely to increase the test count.
- Add a regression test when fixing a meaningful bug or introducing behavior that should remain stable.
- Avoid unrelated refactoring in the same change.
- Update documentation when user-facing behavior, installation, or CLI usage changes.

## Regression workflow

For a behavioral bug:

1. Reproduce and understand the issue.
2. Add a focused regression test that demonstrates the expected behavior.
3. Make the smallest justified production change.
4. Run the complete test suite.
5. Confirm that existing behavior remains intact.

## CLI checks

When changing packaging or command-line behavior, also verify:

```bash
netrecon --help
netrecon examples/sample.xml
```

## Security and authorization

NetRecon is intended for analysis of Nmap XML produced from systems and networks you are authorized to test.

Do not submit examples containing credentials, private keys, secrets, personal information, or sensitive scan data from systems you do not have permission to disclose.

## Pull requests

A pull request should clearly describe:

- what changed,
- why the change is needed,
- how it was tested,
- and any user-visible behavior that changed.

Keep each pull request focused on one logical change whenever practical.

## License

By contributing to NetRecon, you agree that your contributions will be licensed under the project's MIT License.

NetRecon was created and is maintained by Deeb Mzareb.
