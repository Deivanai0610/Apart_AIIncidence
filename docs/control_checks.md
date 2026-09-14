# Control checks

These commands exercise the bounded CHIMERA prototype. A passing command is
local engineering evidence for the stated observable behavior. It is not a
research result and does not establish arbitrary container-escape resistance,
production containment, or compliance with a standard.

## CT1: authorized scope

- Command: `python -m pytest tests/docker/test_controls.py::test_ct1_scope -q`
- Observable result: the declared broker actions reach only the authorized local range; forbidden target and direct database attempts fail.
- Artifact: command exit code and UTC timing in `artifacts/runs/verification/<configuration-digest>.json` when the complete CT1-CT5 set passes.
- Limitation: this checks the fixed Docker topology and bounded action API, not arbitrary container escape techniques or host compromise.

## CT2: scoped credentials

- Command: `python -m pytest tests/docker/test_controls.py::test_ct2_credentials -q`
- Observable result: dummy route credentials work only for their declared route and protected operation.
- Artifact: command exit code and UTC timing in `artifacts/runs/verification/<configuration-digest>.json` when the complete CT1-CT5 set passes.
- Limitation: this checks generated dummy credentials inside one local range, not production identity or secret-management systems.

## CT3: canary stop

- Command: `python -m pytest tests/docker/test_controls.py::test_ct3_canary_stop -q`
- Observable result: current and historical canary use is denied, recorded, and triggers the common mandatory response in conditions B-E.
- Artifact: command exit code and UTC timing in `artifacts/runs/verification/<configuration-digest>.json` when the complete CT1-CT5 set passes.
- Limitation: this checks the implemented registry and bounded broker path, not universal decoy coverage or detection outside this environment.

## CT4: stop effect

- Command: `python -m pytest tests/docker/test_controls.py::test_ct4_stop_effect -q`
- Observable result: new attacker work is rejected after acknowledgement and queued or in-flight outcomes remain explicit.
- Artifact: command exit code and UTC timing in `artifacts/runs/verification/<configuration-digest>.json` when the complete CT1-CT5 set passes.
- Limitation: this checks the prototype's stated stop semantics, not persistence across systems or production containment adequacy.

## CT5: provider-failure fallback

- Command: `python -m pytest tests/test_models.py::test_ct5_provider_failure_fallback -q`
- Observable result: a simulated provider failure invokes the fixed local fallback with the same delivered event batch and `ControllerState`; a pre-existing verified restriction remains recorded in that state.
- Artifact: command exit code and UTC timing in `artifacts/runs/verification/<configuration-digest>.json` when the complete CT1-CT5 set passes.
- Limitation: this is a no-network unit test with a simulated failure. It does not execute Docker enforcement or CT4 stop-effect verification, and it does not verify live provider availability, compatibility, latency, or behavior.

## Verification record

`python -m chimera checks` runs CT1-CT5 as fixed argument arrays. It writes a
success record only after every command exits zero. The record includes the
exact command arrays, exit codes, UTC start and end times, current configuration
digest, source-tree digest, exact attacker and defender model IDs, and Git revision
when available. The live gate rejects the record after a covered source or model
ID changes. The record is local command evidence, not a measured experiment
outcome.

## Active OpenRouter adapter check

- Check date: 2026-09-13.
- API contract: [Send chat completion request](https://openrouter.ai/docs/api/api-reference/chat/send-chat-completion-request?explorer=true). Both roles use the fixed `POST https://openrouter.ai/api/v1/chat/completions` origin, bearer authorization, `model`, `messages`, `max_completion_tokens`, and response usage `prompt_tokens` / `completion_tokens`.
- Route controls: [List endpoints](https://openrouter.ai/docs/api/api-reference/endpoints/list-endpoints) and [Provider routing](https://openrouter.ai/docs/guides/routing/provider-selection). Non-generation endpoint queries returned the attacker route `reka/fp8` / `Reka` / `z-ai/glm-5.3-20260816` at `$0.936/M` input and `$3.168/M` output, and the defender route `google-ai-studio/flex` / `Google AI Studio` / `google/gemini-3.7-flash-20260813` at `$0.375/M` input and `$1.875/M` output.
- Local enforcement: requests disable fallbacks, require supported parameters, sort by price, cap the role-specific price, require exact returned model and routing metadata, and account usage under one file-backed OpenRouter project and authorization budget.
- Compatibility limit: route discovery did not generate tokens or test model behavior. The one authorized pilot attempt failed during local range startup with zero provider requests and zero recorded cost. The CLI now starts and health-waits the range before constructing provider clients, but live model compatibility remains unverified and another provider attempt requires new authorization.
