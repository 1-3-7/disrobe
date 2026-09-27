# Changelog

## Unreleased

### Changed

- Default `chain.json` uses `disrobe.chain/v2` and omits run timing and worker-count data.
- Default `report.json` uses `disrobe.report/v2` and omits run timing data.
- `--timings` writes those run details to `run.json`, which `disrobe context` can read.
