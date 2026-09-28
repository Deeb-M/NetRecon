# NetRecon Examples

These files are small, safe Nmap XML fixtures for trying NetRecon without scanning a live target.

## `sample.xml`

Use this for the basic report and evidence-based analysis:

```bash
netrecon examples/sample.xml
netrecon examples/sample.xml --analyze
netrecon examples/sample.xml --analyze --format json
netrecon examples/sample.xml --evidence-gaps
netrecon examples/sample.xml --evidence-actions
```

The commands above analyze or plan from existing XML. They do not launch Nmap.

## `before.xml` and `after.xml`

These two scans use the documentation-only TEST-NET address `192.0.2.10` and identical TCP/8080 coverage. The later scan adds explicit product identification, making the pair useful for evidence-aware comparison.

```bash
netrecon examples/before.xml examples/after.xml --diff
netrecon examples/before.xml examples/after.xml --analysis-diff
netrecon examples/before.xml examples/after.xml --combined-diff
```

The exposure comparison shows the changed service context. The analysis comparison demonstrates that a previously observed missing-product finding is no longer observed once product evidence exists, without treating missing evidence as proof of remediation.

## Live collection

The examples above are intentionally offline. Workflows such as `--discover`, `--investigate`, `--investigate-collect`, and `--collect-evidence` can invoke Nmap. Use those only against systems and networks you are authorized to test.

For the full workflow guide, see [../USER_GUIDE.md](../USER_GUIDE.md).
