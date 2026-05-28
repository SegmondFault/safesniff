# SafeSniff

SafeSniff is a Rust-based, low-impact TCP service discovery tool for defensive
security assessment. It inspects an authorised IPv4 host or small subnet and
writes a structured JSON report to stdout.

It is intended for small organisation reviews, lab validation, and
`scan-assess` module use. SafeSniff does not exploit services, attempt
credentials, brute-force, persist, modify remote systems, or capture packets.

## Standalone Use

Build and run locally:

```sh
cargo build --release
./target/release/safesniff --help
```

Detect the default local target without scanning:

```sh
./target/release/safesniff --detect-target
```

Run a light scan against one host:

```sh
./target/release/safesniff --profile light --target 192.168.1.10
```

Run a thorough scan against an authorised `/24` or smaller subnet:

```sh
./target/release/safesniff --profile thorough --target 192.168.1.0/24
```

Adjust TCP timeout when needed:

```sh
./target/release/safesniff --target 192.168.1.10 --timeout-ms 700
```

The default profile is `thorough`. The `light` profile checks a smaller set of
common ports.

## Scan-Assess Module Use

In `scan-assess`, SafeSniff is used as an optional module. The module runner
selects the platform binary, runs the scan with module-owned configuration, and
writes JSON evidence for the assessment report.

This keeps scan orchestration generic: `scan-assess` discovers and runs modules,
while SafeSniff owns its own target selection, scan profile, timeout, and output
schema.

## What It Reports

SafeSniff reports:

- target and target-detection metadata
- scanner host metadata
- tested host and port counts
- observed active hosts
- open TCP services and banners where safely available
- likely device role and operating-system hints
- service exposure severity labels
- safety metadata confirming no exploit, credential, brute-force, persistence,
  or packet-capture behaviour

The output is designed to be machine-readable first, with enough context for a
human or LLM-assisted report to explain what was observed and what should be
reviewed.

## Scope And Safety

Only run SafeSniff against systems and networks you are authorised to assess.
The default automatic target detection refuses to scan networks larger than
`/24`; explicit targets must also be `/24` or smaller in the safe default build.
