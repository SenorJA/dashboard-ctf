# REPO ANALYSIS — 2026-10-08

Análisis de tres repos de LLM‑security tooling para decidir el enfoque del **Pack 18** de M.I.R.V. La decisión final fue **port del LLM Security Scanner de praetorian-inc/augustus** como módulo `backend/llm_scanner.py`.

## Candidatos

| Repo | Autor | Rama/core | Estado en Pack 18 |
|------|-------|-----------|-------------------|
| `e2b-dev/e2e` | e2b | e2e evaluation framework (eval-driven) | ❌ Descartado |
| `reAsonance/rea` | reAsonance | REA (Reinforcement Learning from Agent Feedback), RL training loop | ❌ Descartado |
| `praetorian-inc/augustus` | Praetorian | LLM Security Scanner — probes jailbreak/inject + detectores + buffs + Crescendo | ✅ **Elegido (port)** |

## Por qué augustus

- **Enfoque en testing de seguridad del LLM**, no en entrenamiento (REA) ni en infraestructura de eval (e2e). Encaja con el rol de M.I.R.V. (scanner de vulnerabilidades).
- **Solo-stdlib viable**: Augustus está en Go con LLM-interop local, pero su mecánica es portable a Python puro (probes → mensajes, detectores → regex/heurísticas deterministas, buffs → encoders, Crescendo → secuencia multi‑turn fija). M.I.R.V. conserva la invariante `test_pack_purity.py`: sin BD ni red, módulos en stdlib.
- **Determinismo**: v1 comercial de Augustus arrastra LLM-judges; el port a `v2` M.I.R.V. usa solo detectores deterministas (substring/word/regex/plain-json/mitigation) + `Crescendo-lite` con judge heurístico tópico → reproducible y testeable sin API keys.
- **e2e (e2b)**: requiere framework de eval + runners en la nube; demasiado acoplado y fuera de los invariantes.
- **REA (reAsonance)**: es entrenamiento RL, consumo de cómputo alto, sin correlato de "finding" accionable para el panel.

## Alcance del port (Pack 18)

- **23 probes** (familias: goodside 6, dan 4, promptinject 3, prefix 1, donotanswer 5, continuation 1, leak 1, glitch 1, crescendo 1).
- **22 detectores** deterministas (substring/word/regex + variantes, mitigación por prefijos, plain-json, markdown-exfil, token-smuggling, glitch, crescendo-judge).
- **8 buffs encoder** (base64/base32/hex/rot13/atbash/leet/morse/charcode).
- **Generadores** hijack (15), prefix (220), continuation.
- **Crescendo-lite** multi-turn determinista (CONTEXT → MECHANISMS → FAILURE_MODES → OFFENSIVE_APPLICATION), `max_turns` configurable.
- **Registry LRU (20)** + `RunReport` con veredicto por attempt (max elemento-wise primario+secundario, `VULN_THRESHOLD=0.5`).
- **`finding_from_attempt`** → payload `db.save_finding` (`tool=llm-scanner`, `service=llm`, severidad por probe), con SIEM (`source=llm`), audit y notificación high/critical.
- **Endpoints** `/api/llm/*` (7) y **tab UI** `LLM Security` con i18n es/en.
- **48 tests** (37 módulo + 11 endpoints); suite completa **5231 passed, 1 deselected**.

## Semántica de veredicto (fidelidad Augustus)

En Augustus cada probe declara **solo su detector primario** en el YAML; el veredicto es el **max elemento-wise** sobre los detectores efectivamente declarados (primario + secundarios explícitos). El port lo replica: solo un subconjunto de probes lleva secundarios (`goodside.PayloadSplitting`/`ChatMLExploit` → `goodside.SystemOverride`; `dan.AntiDAN` → `dan.AntiDAN`; `leak.ApiKey` → `mitigation.Prefixes` + `goodside.SystemOverride`).