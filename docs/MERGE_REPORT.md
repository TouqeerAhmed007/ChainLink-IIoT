# Merge report

## Source -> destination map
| Chat | Files | Placed at |
|---|---|---|
| 1 | crypto.py, models.py, state.py | iiot/common/ |
| 1 | device.py | iiot/device/ |
| 1 | __init__.py (empty) | iiot/__init__.py |
| 1 | test_crypto_device.py | tests/ |
| 1 | INDEX.md, PACKAGE_SUMMARY.md, README.md | docs/chat1_notes/ |
| 2 | tree.py, registry.py, merkle/__init__.py | iiot/merkle/ |
| 2 | log.py, tls.py | iiot/common/ |
| 2 | serve.py | iiot/fog/ |
| 2 | test_merkle_registry.py | tests/ |
| 3 | app.py, onboarding.py, fog/__init__.py | iiot/fog/ |
| 3 | test_onboarding.py (was iiot/tests/) | tests/ |
| 4 | policy.py, tokens.py, revocation.py, access.py | iiot/fog/ |
| 4 | test_access.py | tests/ |
| 5 | __init__.py (shared helpers) | iiot/attacks/__init__.py |
| 5 | replay, tamper, stolen_token, expired_revoked, extra_attacks, run_all | iiot/attacks/ |
| 5 | run_demo.py | iiot/demo/ |
| 5 | test_attacks.py | tests/ |
| 6 | bench, individual_vs_batch, plots, run_all_perf | iiot/perf/ |
| 6 | README.md, requirements.txt | project root |
| 6 | test_perf_smoke.py | tests/ |

## Changes made while merging (no logic changed)
1. Added pytest.ini (pythonpath=.), .gitignore, empty package __init__.py files for common/, device/, demo/.
2. results/ lives at iiot/results/ (perf code and demo resolve it as iiot/results).
3. demo --tls: server subprocess now gets --cert-dir certs so the demo verifies against the same cert the server uses.
4. README: install/test/attack/demo commands corrected for the merged layout.

## Not included on purpose
- chat1/files/**: a Firefox profile, Windows Prefetch/NTUSER.DAT/event logs and dog.png. Unrelated to the project and contains personal browser data. Not opened, not copied.
- *.pyc, CACHEDIR.TAG, nodeids (pytest cache leftovers).

## Verification status
- Verified here: every .py compiles; every `from iiot... import name` resolves to a real definition; crypto, Merkle (sizes 1..33, tamper, order independence, 10k leaves in ~0.15 s), and registry (chain, tamper detection, persistence) behave as specified.
- NOT executed here (sandbox has no network, so fastapi/pydantic/httpx/pytest/rich could not be installed): the fog HTTP flow, all pytest suites, attacks, demo, perf. Run `pip install -r requirements.txt && python -m pytest` on your machine first.

## Known limitations (candidates for the next prompts)
- A fog restarted with registry_path pointing at an existing file starts current_epoch=0 and will raise on the first batch close (registry already has epoch 1). Fog state is not restored.
- Sessions in state.sessions are never garbage-collected.
- tests/ mixes locations from different chats; now all under tests/.
