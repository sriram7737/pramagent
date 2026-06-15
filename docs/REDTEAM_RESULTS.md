# Red-team Benchmark Results

This is a small built-in prompt-injection sanity check, not a professional red
team and not proof of jailbreak resistance.

## Command

```bash
python -m pramagent.cli redteam --json --dynamic --attacks 200 --seed 999
```

## Current Result

Last refreshed: 2026-06-15

```json
{
  "attacks_bypassed": 0,
  "attacks_caught": 200,
  "attacks_total": 200,
  "benign_total": 6,
  "bypass_rate": 0.0,
  "false_positive_rate": 0.0,
  "false_positives": 0,
  "mode": "dynamic",
  "seed": 999
}
```

## Methodology

- Classifier path: zero-dependency keyword fallback.
- Attack corpus: 200 runtime-mutated prompts generated from
  `pramagent.redteam.EXTENDED_ATTACKS`, including v0.5.8 generated-failure
  classes for malware/data theft, self-replication/spreading behavior,
  privileged-role sensitive-log access, trusted-advisor sensitive-data
  elicitation, admin-privilege confidential-file access, the v0.7.3
  security-prompt regressions for base64-encoded payloads,
  translation-wrapper attacks, and authority-framing attacks, plus the v0.7.5
  dynamic-regression fixes for padded base64 tokens, indirect exfiltration
  wrappers, and inline developer-message wrappers.
- Dynamic seed: 999. Re-run with another seed to explore different mutations.
- Benign corpus: 6 normal prompts shipped in `pramagent.redteam.DEFAULT_BENIGN`.
- Passing threshold used in release smoke tests: bypass rate must be `<= 0.10`.

## Honest Interpretation

The current benchmark now includes deterministic runtime mutation, so it is less
overfit than a fixed prompt list. The v0.7.5 corpus also includes the exact
failure classes found by the active security prompt and public-demo bulk test.
It is still not proof of
jailbreak resistance: the seed corpus and mutation templates are public.
Pramagent still needs larger third-party red-team sets, stronger semantic
classifiers, and continuous adversarial testing before high-stakes claims.
