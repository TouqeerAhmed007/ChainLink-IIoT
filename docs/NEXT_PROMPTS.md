# Prompts for the remaining work

Paste the PROJECT CONTEXT block at the top of every chat, then that chat's prompt. Attach the merged project zip (or the files named in the prompt). Rule for all chats: do not change public interfaces (function names, endpoints, reason codes, CSV columns) unless the prompt says so; report any change in 3 lines max.

## PROJECT CONTEXT (paste first)
```
Project: single-zone IIoT decentralized identity framework (university assignment, 1 fog node, simulated devices). Python 3.11, FastAPI, httpx, cryptography, pydantic, pytest, matplotlib, numpy, rich.
Layout: project root has iiot/ (common, device, merkle, fog, attacks, demo, perf, results), tests/, docs/, README.md, requirements.txt, pytest.ini.
Crypto: P-256 ECDSA (DER hex sigs), pk = uncompressed SEC1 hex, DID = "did:iiot:"+sha256(pk)[:32], leaf = sha256(did||pk), Merkle node = sha256(0x01||left||right), sorted deduped leaves, odd node duplicated, proof steps {"hash","side"}.
Fog API: /auth/hello, /auth/psk, /register/key, /register/pop, /admin/batch/close, /proof/{did}, /epoch/{n}, /registry, /token/temp, /resource/access, /admin/revoke, /status/{did}.
Reason codes: OK, BAD_TOKEN_SIG, TOKEN_EXPIRED, TOKEN_REVOKED, DID_REVOKED, NONCE_REUSED, BAD_REQUEST_SIG, DID_MISMATCH, PROOF_INVALID, UNKNOWN_EPOCH, STALE_TS, POLICY_DENIED, UNKNOWN_DEVICE, SCOPE_DENIED.
Assignment requires: 3 phases (batch registration, temp-token bridging, proof verification + ALLOW/DENY), revocation, >=3 attacks, perf evaluation (5,10,25,50,100 devices, 3 graphs, batch vs individual), 10-step live demo, 6-8 page report, README, contribution table.
Working rules: be token-efficient, no tutorials, complete files only, run tests if you can execute code, finish with a summary of at most 5 lines.
```

## P1. Integration QA and bug fixing (do this first, on your own machine)
```
I will paste the output of `pip install -r requirements.txt && python -m pytest -x` and then of `python -m iiot.attacks.run_all`, `python -m iiot.demo.run_demo`, `python -m iiot.perf.run_all_perf --counts 5 10 --runs 2`. For each failure: identify the root cause, name the single file to change, and give a minimal patch (unified diff). Do not refactor. If a failure is a contract mismatch between two modules, say which side should change and why. After patches, list any test you would add to prevent recurrence.
```

## P2. End-to-end integration tests (tests/test_integration.py)
```
Write tests/test_integration.py using only the public HTTP API through TestClient and SimDevice (make_fleet, onboard_fleet). Cover: (1) full lifecycle: onboard 8 devices, temp token ALLOW while pending, batch close, fetch_proof, proof-mode ALLOW/DENY (temperature_sensor WRITE temperature=ALLOW, STOP production_line=DENY POLICY_DENIED), revoke, same request DENY DID_REVOKED, next batch excludes revoked (excluded_revoked==1), old epoch proof still verifies against old root but access is DENY; (2) late device joins after epoch 1, uses temp token, appears in epoch 2 with stable epoch-1 proofs for old devices; (3) two devices in one batch share one root; (4) concurrent replay: 20 threads send the same body, exactly one ALLOW; (5) registry chain_valid after 5 epochs and tampering a block makes verify_chain False; (6) every response of /resource/access contains decision, reason, checks, latency_ms. Keep each test under 30 lines. Also add a pytest marker `slow` for anything over 2 s.
```

## P3. Fog state persistence and hardening
```
Files you may edit: iiot/fog/app.py, iiot/fog/onboarding.py, iiot/common/state.py, iiot/merkle/registry.py, plus new tests/test_persistence.py.
Tasks: (1) When FogConfig.registry_path points at an existing chain, create_app must restore current_epoch from registry.latest_epoch() and rebuild state.epochs roots so old epochs stay verifiable (proof-mode with epoch<=latest must still find get_root). Persist devices and EpochRecords to a sibling JSON file (atomic write, same tmp+rename pattern) and reload them, so a restarted fog keeps proofs. (2) Garbage-collect expired sessions (older than 10 min, or unauthenticated older than challenge_ttl_s) with an amortized sweep, not per request. (3) Cap total sessions (e.g. 10000) and return 429 beyond it. (4) Reject request bodies over 64 KB on /resource/access with 413. (5) Fix nothing else. Add tests for restart-recovery, session GC and the caps. Keep all existing tests green.
```

## P4. Extra measurements and TLS overhead (assignment "optional" items)
```
Files you may edit: iiot/perf/bench.py, plots.py, run_all_perf.py, README.md (CSV dictionary), new iiot/perf/extras.py, tests/test_perf_smoke.py.
Add, without changing existing CSV columns or metric names: (1) proof size in bytes (canonical JSON of proof) and token size in bytes per N, (2) peak memory of the fog process during a run (tracemalloc or resource), (3) CPU time per phase via time.process_time, (4) concurrent request handling: ThreadPoolExecutor with 1, 4, 16 workers issuing proof-mode ALLOW requests, report requests/s and p95 latency, (5) TLS overhead: start `python -m iiot.fog.serve` with and without --no-tls on localhost, register 25 devices via httpx, compare registration latency (skip gracefully if the port is busy). Write results to results/extras.csv and graph5_extras.png (dpi 200). Extend the smoke test with counts [5] runs 1. Update README.
```

## P5. Demo rehearsal kit and viva Q&A
```
Read iiot/demo/run_demo.py and the fog code. Produce docs/DEMO_SCRIPT.md: a 12-minute script for three presenters (student A: phases 1 and batch; B: tokens, verification, revocation; C: attacks and performance) with exact commands, what each step prints, the sentence to say at each ALLOW/DENY, and 2 fallback commands if the live demo fails (in-process mode, pre-generated results). Then write docs/VIVA_QA.md: 30 likely questions with 2-3 line answers each, grouped by phase, referencing exact files/functions (e.g. why leaves are sorted, why nonce is recorded only on ALLOW, why token alone is insufficient, what happens to old proofs after revocation, batch vs individual cost, why the root is read only from the registry). Also add `--fast` to run_demo.py that skips sleeps in the expired-token attack by using a 1 s TTL only (no other behavior change).
```

## P6. Security review of the implementation
```
Review iiot/fog/*.py and iiot/common/*.py as a security auditor for this assignment's threat model (network attacker, malicious device, stolen token). Output a table: finding, file:line, severity, exploit in one sentence, minimal fix. Check specifically: timing leaks, nonce store growth and eviction, ts skew window vs nonce TTL (must be >= 2*skew), token payload fields trusted without validation, /proof/{did} information exposure, admin key handling, race conditions between revoke and access, PoP challenge replay, DID squatting via /register/key, canonical JSON float handling for ts, unbounded lists in proof. Then implement only HIGH/MEDIUM fixes with tests in tests/test_security.py. Do not change the contract.
```

## P7. Report (docs/REPORT.md, 6-8 pages) 
```
Write the implementation report in Markdown following the assignment's section list: architecture and component diagram (Mermaid), technologies and primitives, Phase 1, Phase 2, Phase 3, revocation, attacks (setup, expected, actual, detector, from iiot.attacks.run_all output), performance (environment.txt, methodology, tables and graph references from results/), batch vs individual, selected logs, problems and design decisions, individual contribution table (leave names blank, fill files/functions/tests per the module ownership: student1 = common+device, student2 = merkle+registry+log+tls+serve, student3 = fog onboarding, ... assign 2 chats per student). Use only facts present in the code and results; where a number is missing write "<<fill from results>>". ~3000 words, tables over prose. I will paste run_all output and results/summary.csv.
```

## P8. Git history and CI
```
Give me: (1) a plan of 25-30 realistic commits, in order, per student (3 students, 2 chats each), each with message, files, and the command to stage only those files so the history reflects individual authorship of the merged repo; (2) .github/workflows/ci.yml running pytest on Python 3.11 and 3.12 plus `python -m iiot.attacks.run_all`; (3) a CONTRIBUTING-style table for the report. No code changes.
```
