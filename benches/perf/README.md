# Behaviour gate

`manifest.toml` lists committed inputs, and `golden.txt` records what `disrobe auto` produced for each of them: the exit status, the BLAKE3 hash of the input, of stdout and of stderr, the hash of every output file, and every empty output directory. `cargo xtask golden check` runs the CLI on the inputs again and fails on any difference.

## Run it

```sh
cargo build --locked --profile ci -p disrobe-cli --bin disrobe
cargo xtask golden check --bin target/ci/disrobe                   # every input
cargo xtask golden check --bin target/ci/disrobe --subset          # the inputs marked `subset`
cargo xtask golden check --bin target/ci/disrobe --only go-garble  # one input
```

`record` takes the same options and rewrites `golden.txt`; with `--subset` or `--only` it replaces only the selected entries. `--jobs` sets how many inputs run at once (at most 8 by default), and `--timeout-secs` bounds each run (1800 by default).

## What each run sees

Each input is copied to `<work>/in/<id>/`, and the CLI runs from the work directory with relative paths:

```sh
disrobe --config golden.disrobe.toml auto in/<id>/<file> -o out/<id> --force --progress never --json
```

The environment is cleared, then:

- `PATH` names an empty directory, so no installed formatter, compiler, interpreter, or archive tool is found.
- The home, application-data, and XDG variables name an empty `home` directory, and the temporary-directory variables name a directory of the input's own.
- `SOURCE_DATE_EPOCH` is `0`.
- The configuration file is empty, so no `.disrobe.toml` elsewhere is read.

The work directory defaults to `target/golden`, or `golden` under `CARGO_TARGET_DIR`. The gate clears it only when it carries the `.xtask-golden` marker that the gate writes.

## What is normalized

- `duration_ms` and `total_ms` values in stdout and in the top-level `chain.json`, `recovery.json`, `report.json`, and `report.sarif`, because they measure time.
- Timestamps and thread IDs in stderr.

Nothing else is rewritten.

## What fails

- A different exit status, input, stdout, stderr, output file, or empty directory; an input that is new, missing, or no longer in the manifest.
- A run that times out.
- Output, stdout, or stderr that names the work directory, the directory of the binary, or the checkout.
- A run that changes its input, writes beside it, leaves files in its temporary directory, or writes into the home directory, the empty `PATH` directory, the work directory, or the configuration file.
- An output entry that is neither a file nor a directory.
- An input that git does not track.

A change that alters output on purpose updates `golden.txt` in the same commit and says why.
