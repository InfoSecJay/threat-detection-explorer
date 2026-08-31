# Contributing to Detection Explorer

Thanks for wanting in. This project has a way in for every level of
effort -- you do not need to write code to make it better.

## Suggest a detection-rule source

The highest-value contribution. If a public repository of detection
rules is missing, open a
[source suggestion](https://github.com/InfoSecJay/threat-detection-explorer/issues/new?template=suggest-a-source.md)
with the repo URL, the rule format, and roughly how many rules it
holds. What gets a source accepted:

- **Public and licensed** -- a LICENSE we can honor (we display
  per-source licenses on every rule page).
- **Real detection rules** -- alerting/correlation logic, not IOC
  feeds, hunting notebooks, or config baselines.
- **Maintained** -- commits within the last year.
- **Distinct signal** -- coverage the existing thirteen sources do not
  already provide.

## Report a wrong extraction or mapping

If a rule page shows a wrong observable (a process name that is
actually a path, a mis-typed event ID), a wrong platform/data-source
mapping, or a search result that should not match: open an issue with
the rule URL and what you expected. These fix classes of bugs, not
single rules -- the extraction test suites grow with every report.

## Code

```bash
git clone https://github.com/InfoSecJay/threat-detection-explorer.git
# backend: python 3.11+, venv, pip install -r backend/requirements.txt
# frontend: node 18+, npm install
```

Ground rules (enforced by CI and review):

- Backend changes run `pytest` green (`backend/tests/`, 1300+ tests);
  frontend changes pass `tsc --noEmit`, `eslint --max-warnings 0`, and
  `vitest run`.
- Parser/extractor changes need fixture tests demonstrating the rule
  text they fix -- see `backend/tests/test_services/test_*_review_*.py`
  for the pattern.
- Taxonomy mapping edits (`backend/app/services/taxonomy/mappings/`)
  must use canonical vocabulary (`canonical.py`); the mapping-integrity
  test enforces it.
- Keep diffs reviewable: split refactors from behavior changes.

The full local-dev walkthrough lives in the [README](./README.md#development).

## License

Contributions are accepted under Apache-2.0 (the project license).
The detection rules the site indexes remain under their upstream
repositories' own licenses.
