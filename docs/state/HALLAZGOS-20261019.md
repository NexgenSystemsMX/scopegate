# HALLAZGOS — 2026-10-19

Paso 5 de `docs/METODOLOGIA-SWARM.md`, ciclo 4 (`scopegate-cloud-architecture`). **Auditoría de coherencia
documental**, no de ejecución: este ciclo no produjo código.

- Artefactos auditados: [`FEAT-SCOPEGATE-CLOUD-ARCHITECTURE.md`](../specs/FEAT-SCOPEGATE-CLOUD-ARCHITECTURE.md),
  [`BLUEPRINT-v1.md`](../plans/BLUEPRINT-v1.md), [`BACKLOG-EPICS-v2.md`](../plans/BACKLOG-EPICS-v2.md),
  [`DISENO-SCOPEGATE-CLOUD.md`](../plans/DISENO-SCOPEGATE-CLOUD.md)
- Cierre del paso 4: commit `23080e2`

## 1. Método de esta auditoría

En un ciclo de arquitectura los defectos no son bugs: son **contradicciones entre documentos** y
**promesas sin dueño**. Se auditó con estos cinco ejes:

1. Cada requisito del `FEAT` (R1–R7) y cada criterio (AC1–AC7) tienen cobertura en el diseño.
2. Cada condición del `BLUEPRINT` (§4) está materializada o explícitamente descartada.
3. Cada task del `BACKLOG` (T1.1–T2.1) produce el artefacto que promete, con su criterio verificable.
4. Cada `PENDIENTE` tiene **dueño** nombrado, no un estado.
5. Ninguna sección promete más de lo que el `FEAT` acota.

## 2. Hallazgos

| ID | Severidad | Hallazgo | Evidencia | Estado |
|---|---|---|---|---|
| H-1 | **P2** | **El diseño no respondía qué pasa con un tenant caído**, y el `FEAT` AC4 lo exige explícitamente | `grep -c 'tenant caído' DISENO` → **0** antes; `FEAT` AC4 → «qué ocurre con el cloud caído **y con un tenant caído**» | **CERRADO**: §1.4 punto 6 — fallo de un tenant = deny para ese tenant, purga de sus leases, los demás siguen operando |
| H-2 | **P3** | **Ambigüedad en R7**: «la misma cadena de hashes y firma que hoy» podía leerse como una única cadena global, y el diseño §4.3 la parte en dos cadenas por productor | `FEAT:64` vs `DISENO:166-175` | **CERRADO**: §4.3 declara la interpretación (mismo formato y firma, no una cadena compartida) y deja la contradicción a la vista si producto quería otra cosa |
| H-3 | **P3** | Dos `PENDIENTE` sin dueño: decían `PENDIENTE: medición`, que es un estado, no un responsable | `DISENO:27-28` | **CERRADO**: pasan a `PENDIENTE: banco de pruebas del proxy (ciclo de implementación)` |
| H-4 | — | El `PENDIENTE: usuario` de la custodia de la KEK quedó resuelto por decisión del usuario (KMS externo) | `DISENO:130-133` | **CERRADO**: la §3 registra la decisión, su fecha y el prerrequisito del issue para `@aws-sdk/client-kms` |

**Nota de proceso**: H-1 a H-3 se cerraron **en la misma pasada**, no se dejaron al Paso 6. Razón: los tres
son omisiones dentro del mismo cuerpo documental que se acaba de escribir, no diseño nuevo; dejar H-1
abierto habría dejado el ciclo reclamando AC4 sin cumplirlo. Queda declarado acá para que no se lea como un
Paso 6 encubierto.

## 3. Cobertura requisito → diseño (los cinco ejes)

| Requisito / condición | Dónde está cubierto |
|---|---|
| R1 (jerarquía KEK/DEK + rotación) | §3, tabla de dos niveles con rotación por nivel |
| R2 (el secreto nunca viaja) | §2.1 («no transporta material secreto»), §4.1 (fila 1) |
| R3 (`max_ttl` sigue siendo techo) | §2.3, fórmula `min(60 s, max_ttl, vida restante)` |
| R4 (indisponibilidad) | §1.4 puntos 1-6, incluido el fail-closed del store |
| R5 (aislamiento por tenant) | §4.2 (tres vectores) y §1.4 punto 6 (aislamiento **de fallo**) |
| R6 (migración sin corte) | §5, fases 0/1/2 con la fase sombra |
| R7 (audit) | §4.3, con la interpretación declarada (H-2) |
| Condición 1 del blueprint (A5: clase de sistema) | §1.1, declarado antes del presupuesto |
| Condición 4 (prohibir caché de secretos) | §6 P1 |
| Condición 5 (KMS con issue) | §3, decisión + prerrequisito |
| Condición 6 (purga al revocar) | §2.4 punto 3 |

## 4. Bugs

Ninguno: no hay código ejecutado en este ciclo.

## 5. Bloqueos

| ID | Qué bloquea | Estado |
|---|---|---|
| BLK-1 | Las cifras de latencia y del banco de pruebas **no se pueden medir sin proxy** | Declarado y con dueño (`PENDIENTE: banco de pruebas del proxy`) |
| BLK-2 | El issue de `@aws-sdk/client-kms` no existe todavía | Prerrequisito del ciclo de implementación; no bloquea el cierre de este ciclo de diseño |

## 6. Seguridad

Cero P0 materializado (no hay código). Siguen **declarados** como bloqueantes del ciclo de implementación:
material secreto dentro de un lease, y reuso de un lease fuera de su tope. El riesgo residual del KMS
(compromiso del plano con acceso al KMS descifra los tenants que ese KMS permita) queda escrito en §3, no
mitigado.

## 7. Veredicto de la auditoría

- **Coherencia**: los cuatro documentos no se contradicen; las dos ambigüedades encontradas (H-1, H-2) se
  resolvieron en el propio diseño.
- **Scope**: ninguna sección promete fuera de lo que el `FEAT` acota. El `FEAT` excluye implementación y
  este diseño no implementa.
- **Promesas sin dueño**: cero. Los tres `PENDIENTE` restantes tienen responsable y momento (banco de
  pruebas del proxy, producto para el SLO).
- **Cero P0/P1 abiertos.** Un P2 y dos P3, cerrados en esta pasada.
