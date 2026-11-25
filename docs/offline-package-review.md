# Offline package review pilot

The probe checks that Goose rejects a cold package cache and typechecks with a
prepopulated cache without starting Git in either case. It uses a fresh home,
a synthetic package and a Git trace positive control. Exit 0 means both cases
passed, 1 means a regression was observed and 2 means investigation is needed.
The workflow records the exact source commit and compiler digest and uploads a
bounded report. Build and infrastructure failures remain visible in CI.

Transfer the JSON artifact as data to the offline review environment. Run the
review with a trusted copy of the script, an isolated checkout of the commit
identified by the report and, when available, a candidate diff.

```sh
python3 /trusted/offline_package_probe.py review \
  --repo /work/goose --evidence offline-package-evidence.json \
  --candidate candidate.patch --out review.json
```

Without a candidate, omit that option to prepare a triage packet. A candidate
is checked against the reported commit without applying it. The report
remains in human-review-required state. The reviewer checks the diff,
reruns the test in the isolated environment and decides whether to publish.
Evidence hashes identify the input artifacts, and the report does not provide
source or workflow authentication by itself. Verify artifact provenance at
the transfer boundary. Keep sensitive security findings in private channels.
