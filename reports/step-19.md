# Step-19 — informe

## Summary

1. T1: el flip pass-through quedó **PROVEN** (regla 44): colisión del cache
   de transformaciones de coraza v3.7.0 sobre argumentos con el mismo
   nombre, vía el orden aleatorio del map en `GetField()/FindAll()`; el
   build scratch sin cache hace 0/2.500 flips vs mediana 114/500.
2. T2: el coste POST del fix de fidelidad se midió (131.071 B text/plain:
   6,0 s PRE vs 17,6–20,1 s POST; **la regla 942100 sola reproduce TODO el
   coste añadido**, bisect DIAGNOSTIC); T3: bajo ataque de bodies lentos el
   engine queda en starvation total de POSTs benignos con body (0/131
   servidos, 2.154 CPU-s) — DIAGNOSTIC, E29 failing-by-design, sin fix.
3. T4: el scope final (166 updates, 921 excluido) se evaluó en datos NO
   vistos (benign-wcp-v1, preregistrada, ids disjuntos): **new blocks
   PL1 = 28 / PL2 = 14**, idénticos entre corridas (3 flips PL2 = el
   defecto PROVEN), 0 timeouts. A2: connector 1.868/4.480 vs engine
   1.092/4.436 — la masa connector-only sigue siendo la política CT
   (920420, DESIGN). A3: 0/100 matches del engine en los ids 920420.

## Host (regla 43)

Ubuntu 26.04.1 LTS, kernel 7.0.0-44-generic, go1.25.0 linux/amd64, Python
3.14.4 (.venv), **docker 29.1.3 + compose 2.40.3** (instalado por el
usuario), 8 cpus, VM de escritorio con carga ruidosa (1,3–6,6 durante las
corridas). Imágenes pinned: coraza-crs
`sha256:bfbfe70b4445c1ef1dc389c2de12cfdb194c9616746c33dc8a7131461c28f4a6`,
python:3.12-alpine. Regla 29 re-probada por corrida (config efectiva en el
log de cada run).

## Tabla de tareas

| Tarea | Estado | Evidencia |
|---|---|---|
| A1 tokens | DONE | `docs/logs/wcp-v0-token-ids.txt` (8 ids), scrub + 3 tests en el builder |
| A2 connector v1 | DONE | `docs/logs/step19-t2b-a2-analysis.txt`, runs en `docs/logs/runs/coraza-benign-wcp-v1-pl{1,2}-default/` |
| A3 sample 920420 | DONE (2 intentos; 1º invalidado) | `docs/logs/step19-a3-analysis.txt`, `docs/logs/runs/s19-a3-replay-v2/` |
| T1 flips | DONE — PROVEN | `docs/logs/step19-t1-{analysis,nocache,exposure}.txt`, `docs/logs/runs/s19-flip-*` |
| T2 coste | DONE | `docs/logs/step19-t2-{summary,cost,bisect}.txt`, `docs/logs/runs/s19-t2-*` |
| T3 disponibilidad | DONE (DIAGNOSTIC) | `docs/logs/step19-t3-availability.txt`, `docs/logs/runs/s19-t3-availability/`, E29 |
| T4 held-out v1 | DONE | `docs/plan-benign-wcp-v1.md`, `docs/logs/step19-t4-{runs,analysis}.txt`, 8 runs en `docs/logs/runs/s19-t4-*` |
| T5 docs + E16×10 | DONE | `docs/baseline-v1.4.md`, `docs/logs/step19-e16x10.txt`, acceptance E27–E29, decisión 0004, README |

## T1 — flips: PROVEN (regla 44)

- Reproducer commit-first (`tools/flip_repro.py`): 2 muestras con DOS args
  con el mismo nombre `filter` (wcp-62cd1bd36bf7, wcp-b6f2246ef4b8), 500
  rondas PL2. Flips/500 en 5 procesos frescos: 114/111/122/117/113.
- Experimentos discriminantes (5×500 c/u, mismo binario): GOGC=off
  110/111/94/107/107; GOGC=1 122/108/115/122/108; GOMAXPROCS=1
  121/111/122/126/113; build `-race` 56/300 rondas, 0 reportes de race →
  hipótesis GC y data-race RECHAZADAS.
- Captura de divergencia (E28 debug logger, DIAGNOSTIC): mismo sample,
  mismos valores de args — 942370 MATCH en la tx que bloquea y NO MATCH en
  la que pasa; 942430 2 vs 0. La divergencia está dentro de la evaluación
  del operador.
- **Causa raíz PROVEN en el fuente de coraza v3.7.0**:
  `rule.go transformArg()` cachea por
  `transformationKey{argKey: unsafe.StringData(arg.Key()), argIndex: i}`;
  `argIndex` es la posición en `tx.GetField()` → `FindAll()`, que itera
  `c.collection.data` — un **map de Go con orden aleatorio**
  (`internal/collections/named.go:155`). Con dos args homónimos, el índice
  aleatorio es lo único que distingue las claves → se cachea/lee la
  transformación del arg EQUIVOCADO → misses intermitentes.
- **Experimento discriminante final**: copia scratch de coraza con el cache
  bypassado en `transformArg` → 5×500 = **0/0/0/0/0 flips (0/2.500)** vs
  mediana 114/500 con cache (`docs/logs/step19-t1-nocache.txt`).
- No es corregible en el build enviado (el cache es interno a coraza; ninguna
  config lo desactiva) → exposición documentada, sin mitigación inventada:
  **498/20.000 muestras de benign-wcp-v0 tienen ≥2 args homónimos**
  (`docs/logs/step19-t1-exposure.txt`). Subir de versión de coraza = decisión
  del instructor (issue upstream #1815 reconoce el no-determinismo del orden
  del map; las release notes de v3.8.1 no listan el fix del cache-key).
- E27 (test-first): todo request deja evento block/pass con rule ids en
  `kortex-events.jsonl`. E28: debug logger opcional de coraza.

## T2 — coste en la configuración de envío

Mediana (s, n=3, budget 120.000 ms para dejar terminar la llamada;
`docs/logs/step19-t2-cost.txt`; 3 reps re-lanzadas con readiness probe tras
fallos de arranque — filas RETRY):

| body | PRE PL1 | PRE PL2 | POST PL1 | POST PL2 |
|---|---|---|---|---|
| text/plain 16.384 B | 0,31 | 0,37 | 0,66 | 0,81 |
| text/plain 32.768 B | 0,57 | 0,75 | 1,90 | **2,04** |
| text/plain 65.536 B | 1,34 | 1,56 | 4,57 | 4,89 |
| text/plain 131.071 B | 6,00 | 6,25 | **17,64** | **20,10** |
| text/plain 131.072 B | 5,86 | 6,30 | 17,78 | 19,13 |
| JSON (mismos tamaños) | 0,07–0,47 | 0,13–0,59 | 0,47–1,16 | 0,47–1,52 |

- **Sí hay bodies ≤ cap (131.072) que exceden el budget de 2 s con el
  engine POST**: el más pequeño es **32.768 B text/plain en PL2** (mediana
  2,04 s; en PL1 el más pequeño es 65.536 B, 4,57 s). En el propio cap la
  llamada tarda 17,6–20,1 s ≈ 10× el budget. Con el budget real de 2 s
  estas llamadas se abandonan fail-closed a los 2 s (503) y siguen
  consumiendo CPU (~18–24 s: ver T3).
- Muestras WCP >1 s (post-fix): 3 PL1 + 3 PL2 (los de PL2 son nuevos por el
  fix), todas timeouts de budget; ids, bytes, ct y reglas dominantes en
  `docs/logs/step19-t2-slow-samples.txt` + replay a 120 s
  (`docs/logs/runs/s19-t2-slow-replay/`): las uma/no-ct dominadas por
  920270/920271/920240/921150/932130/932230; la JSON por
  920230/931130/932236/942200/942340/942370.
- **Coste por regla (DIAGNOSTIC, bisect con binario scratch y filtro env de
  las 166 updates; prueba de config por run en
  `docs/logs/step19-t2-bisect-configs.txt`)**: body 131.071 B PL2 —
  all-166: 19,0–21,1 s; cada familia sola (930/931/932/933/934/941):
  6,2–7,2 s (= baseline); 942 sola (55 updates): 18,8–19,5 s; 9421xx:
  17,4–19,8 s; **942100 SOLA (1 update): 17,7–19,9 s**; 942101 (0 updates):
  6,7–7,3 s. → **La regla 942100 (libinjection SQLi) sola reproduce todo el
  coste añadido**: su cadena de transformaciones corre sobre el body crudo
  completo por request.

## T3 — disponibilidad bajo bodies lentos sostenidos (DIAGNOSTIC)

Config por defecto (cap 8, inspected 131.072, budget 2.000 ms, PL1). 8
workers re-enviando el body text/plain de 131.071 B durante 5 min; 1 POST
benigno con body + 1 GET benigno por segundo
(`tools/run_step19_t3_availability.sh`):

- **Tasa de éxito del POST benigno con body: 0/131** (129×503 overload,
  2 otros). Los 8 slots quedaron clavados por requests cuyo procesado se
  abandona a los 2 s pero sigue corriendo: 102 llamadas abandonadas,
  hold mediana 23,7 s / máx 33,0 s.
- GET benigno (sin slot): mediana 521 ms, p90 3.218 ms, máx 6.262 ms —
  degradado pero nunca starvation.
- CPU: el engine consumió **2.154 CPU-segundos en ~306 s** (~7 de 8
  núcleos); load 1,27 → 10,39. Rechazos overload: 8.292.
- Recuperación: el path de respuesta vuelve en la primera sonda tras parar
  el ataque; el drenaje de CPU sigue hasta ~33 s (hold máximo). (La sonda
  de recuperación esperaba status 200 pero el stub responde 501 al POST —
  defecto del harness de medición, no del engine; las filas muestran el
  pass-through inmediato.)
- **E29 (failing-by-design, test-first)**: documenta la starvation (un
  POST benigno con body debe ser servido con los slots clavados). Falla
  en la 1ª suite completa y pasó en la 2ª (sensible al timing del
  slot-holding); la evidencia autoritativa es la corrida T3 de 5 min.
  **No se propone fix** (decisión del instructor).

## T4 — scope final en datos NO vistos (benign-wcp-v1, HELD-OUT)

- Preregistrado ANTES de construir (`docs/plan-benign-wcp-v1.md`, commit
  a7a6224): seed 1, 10.000 muestras, cap 2%/sitio (200; máx real 160),
  índices globales de v0 excluidos → **ids disjuntos (intersección 0,
  verificado)**. El builder se generalizó con CLI (defaults de v0 intactos).
- Regla 45: la exclusión de REQUEST-921 y la lista de 166 targets se
  derivaron de **benign-wcp-v0 → IN-SAMPLE**; benign-wcp-v1 y
  benign-browse-v1 son HELD-OUT (marcado corregido en engine-design.md).
- Credenciales (regla 25): cookies dropped 6.677, authorization 259,
  email-like contados 73+2, API-key-like 153, **tokens publicables
  REDACTADOS 2 (scrub A1)**; 0 `pk.eyJ`/`sk.eyJ` en el manifest (verificado).
  **No se commitean manifest/annotations**; se commitean plan, sample-plan,
  MANIFEST.sha256 y builder. **Hash de rebuild verificado idéntico**
  (`049b7dea…`).
- 8 corridas (PRE/POST × PL1/PL2 × 2), workers 1, engine fresco por run,
  prueba de config por run (166 updates POST / 0 PRE), artefactos
  preservados (regla 42). Load average por run en run.json.

| PL | POST r1 | POST r2 | PRE r1 | PRE r2 | NEW BLOCKS (post−pre) |
|---|---|---|---|---|---|
| 1 | 1.092 | 1.092 | 1.064 | 1.064 | **28** (28 en AMBAS corridas) |
| 2 | 4.436 | 4.437 | 4.424 | 4.424 | **14** (14 en AMBAS) |

- Desacuerdo run-a-run del MISMO binario: PL1 = 0; PL2 = 3 ids
  (wcp-464f59067651, wcp-5d3fca6ceb20, wcp-81f2f8b2c3e0) = el defecto
  PROVEN del cache de coraza (T1). Timeouts/errores: **0 en las 8 corridas**.
- Composición de los new blocks (regla 46: son NEW BLOCKS sobre tráfico
  benigno, no "gains"; conteos, regla 35):
  - PL1 (28): 949110×28 (fase de bloqueo de la cadena libinjection 942100),
    932370×16, 932235×6, 932125×5 (familia RCE), 942550×3, 933120×3;
    content: text/plain ×17, urlencoded ×10, csp-report ×1.
  - PL2 (14): 949110×14, 942430×11, 942440×2, 942120×2, 932240×5,
    932236×1, 932370×1, 932380×1.
- Comparación con v0 (IN-SAMPLE, step-18): 61/29 → held-out v1 **28/14**,
  menor: sin señal de overfitting del scope.

## A2 — connector en el held-out (regla 32, per-id)

Connector (coraza-crs pinned, crs_setup_version=4252, límites
13107200/131072 probados in-container): PL1 **1.868**, PL2 **4.480**.
Engine POST: 1.092 / 4.436.

| PL | comunes | solo-connector | solo-engine |
|---|---|---|---|
| 1 | 1.080 | 788 (754 = engine pasa → stub 501; 26 = 404; 8 = 413; reglas: **920420×784** = política CT, DESIGN-C4) | 12 (fidelidad REQUEST_BODY) |
| 2 | 4.426 | 54 (**920420×49**; 14×404, 9×413, 29×501, 2×503) | 10 |

La asimetría sigue siendo la política de Content-Type (diseno C4), ahora
confirmada en datos no vistos; el engine además bloquea por las adiciones
de fidelidad que el connector stock no tiene.

## A3 — sample de los 1.637 ids 920420 (v0, PL1)

- Muestra: 100 ids con body (de 1.499 con body), `random.Random(42)`.
- **Primer intento INVALIDADO**: un replay manual duplicaba User-Agent y
  Content-Type (case-sensitivity del dict) → el engine veía 2 Content-Type
  y bloqueaba 66/100 por scoring (949110, score 8). Documentado, no
  ocultado (regla 4); artefactos en `docs/logs/runs/s19-a3-replay/`.
- **Segundo intento (contrato exacto del runner)**: 100/100 replayados,
  **0 bloqueados, 0 entradas de auditoría, 0 reglas matched — 0/100
  body-derived, 0/100 detección**. El connector bloquea por 920420 (política
  CT) antes de inspeccionar; el engine (C4) acepta el CT, inspecciona y no
  encuentra nada. Limitación: el audit del engine no registra evaluaciones
  sin match, así que lo observable (matches) es 0.
- Nota: la sensibilidad a headers duplicados (2 CT → score 8 → 403) es
  comportamiento CRS correcto, no un bug del engine.

## T5 — estabilidad y docs

- **E16 ×10: 10/10 ok**, wall del test 2,97–4,38 s, load average por rep
  en `docs/logs/step19-e16x10.txt` (VM ruidosa: 4,4–6,6).
- Docs: `docs/baseline-v1.4.md` (nuevo, v1.3 intacto), engine-design.md
  (marca IN-SAMPLE de v0, regla 45), engine-evidence.md vía baseline,
  acceptance.md (E27–E29), decisión 0004 (SIGNE provisional; condición
  coraza también cumplida en held-out), README (conteos).

## Tests

- `go test ./...` en engine/ (con KORTEX_TEST_WCP_BODY): **31 PASS,
  1 FAIL** — el FAIL es E20 (recuperación post-overload 121,3 s > deadline),
  consecuencia conocida del coste 6,2× del fix (decisión pendiente del
  instructor). E19 falló una vez en suite completa por contention de carga
  (load 6,6) y pasa 3/3 aislado — no es regresión.
- `pytest tests/`: **111 passed, 3 skipped** (los +3 son los tests del
  scrub A1).

## Desviaciones de las instrucciones

- El task decía "tools/build_wcp.py"; el builder real es
  `tools/build_benign_wcp.py` (ahí se implementó el scrub).
- La sonda de recuperación de T3 esperaba status 200; el stub responde 501
  al POST — el criterio quedó mal especificado en el harness de medición;
  los datos crudos permiten leer la recuperación real (inmediata).
- A3: el primer replay fue invalidado por el defecto de headers duplicados
  (documentado arriba); el resultado válido es el del runner.

## UNVERIFIED

- Nada en las cifras de arriba: todo sale de comandos y salidas citadas.
- El efecto exacto de una futura versión de coraza (v3.8.1+) sobre el flip
  es UNVERIFIED — requiere bump y re-run (decisión del instructor).

## Preguntas para el instructor

1. **Flip (PROVEN)**: ¿subir a coraza v3.8.x/3.9.x y re-verificar, o aceptar
   la exposición documentada (498/20.000 muestras con ≥2 args homónimos)?
   El fix upstream no está confirmado en release notes.
2. **Coste 6,2× vs E20** (arrastrado de step-18): con el dato nuevo de que
   **942100 sola** explica todo el coste, ¿se acepta un scope más fino
   (p.ej. excluir REQUEST_BODY de 942100, manteniendo ARGS), se sube el
   budget, o se revierte? Cualquier cambio de scope necesita su propio
   ciclo test-first + held-out.
3. **T3/E29**: ¿se quiere un fix de disponibilidad (reserva de slot con
   deadline duro, o cola de espera) o se documenta la starvation como
   limitación?
4. **benign-wcp-v0 congelada** contiene 6 tokens Mapbox publicables
   (regla 25, step-18): ¿re-freezar redactada como v0.1, dejarla, o
   retirarla? (v1 ya nace limpia.)
5. Los 28/14 new blocks del held-out: ¿se aceptan como coste conocido de la
   fidelidad o se abren exclusiones por familia (requeriría ciclo propio)?
