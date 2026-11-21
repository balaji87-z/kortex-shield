# benign-wcp-v1

Segunda versión del corpus benigno WCP (openappsec), construida según
`docs/plan-benign-wcp-v1.md` (preregistrada, step-19 T4).

- Fuente: `legitimate.zip` SHA-256 `58faee18c54229759287a574f6f8cb1e3b951fa135e403ea9a679d2b18efd778`
  (Apache 2.0, commit WCP `8ec8263eebba76816601f7c7052f8ffb83e31312`).
- 10.000 requests distintos, seed 1, cap 2% por sitio (200; máx. real 160),
  692 strata, 689 usados. Índices globales de v0 EXCLUIDOS del muestreo →
  ids disjuntos de v0 (intersección = 0, verificado).
- MANIFEST.sha256: `049b7dea33aac475c4ef7f05c8644da610ad311a84862ef3b88d33a37dc8b5c0`
- Hosts distintos: 2.217. Clases: page 5.835 / static 2.934 / api 1.231.

## Etiquetado (regla 11)

"benign" significa "presente en el set legítimo de openappsec WCP", no
"verificado inofensivo request a request".

## Credenciales y datos personales (regla 25)

Escaneo en build: cookie header dropped 6.677; authorization dropped 259;
email-like en body 73 (contados, no modificados); API-key-like query 153
(contados); email-like en header 2; content-encoding dropped 5; **tokens
publicables (pk./sk. JWT-like) REDACTADOS: 2** (scrub step-19 A1). El
manifest resultante contiene 0 shapes `pk.eyJ`/`sk.eyJ` (verificado).

## Commits

NO se commitean `manifest.jsonl` ni `annotations.jsonl` (datos de tráfico
externo; regla 25 y el incidente de push-protection del step-18). Se
commitean: este README, `sample-plan.json` (índices globales, sin
contenido), `MANIFEST.sha256` y el builder. Con el zip original + sample-plan
el manifest se reconstruye byte a byte (hash verificado en step-19).

## Congelada

El SHA-256 de manifest.jsonl quedó escrito en `MANIFEST.sha256` → versión
congelada (regla 10). Cualquier cambio = nueva carpeta de versión.
