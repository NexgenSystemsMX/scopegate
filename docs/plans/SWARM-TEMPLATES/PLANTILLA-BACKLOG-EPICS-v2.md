# BACKLOG-EPICS v2 — <NOMBRE_TAREA>

Paso 3 de `docs/METODOLOGIA-SWARM.md`. Blueprint premortem + backlog refinado. **Es el único
documento que el paso 4 puede ejecutar.**

- Blueprint de origen: `docs/plans/BLUEPRINT-v1.md`
- Fecha / sesión:

## 1. Premortem (10 roles)

El plan ya fracasó. Por qué, en orden de probabilidad.

| # | Modo de fallo imaginado | Probabilidad | Impacto | Mitigación incorporada al plan |
|---|---|---|---|---|
| 1 | | | | |

## 2. Refutaciones adversariales (5 roles)

| Blueprint afirmaba | Refutación | Resultado |
|---|---|---|
| | | `aceptada` / `rechazada` |

## 3. Veredicto de los jueces (3)

- Plan apto para ejecutar: `sí` / `no`
- Cambios obligatorios antes de ejecutar:
- P0 abiertos (bloquean el paso 4):

## 4. EPICS y Tasks

Formato obligatorio: cada task tiene **exactamente un** criterio de aceptación verificable (1:1).
Una task sin comando o artefacto que lo pruebe no entra al backlog.

### EPIC-1 — <título>

Objetivo del epic en una frase.

| Task | Qué hace | Archivos | Criterio de aceptación (1:1) | Verificación | Estado |
|---|---|---|---|---|---|
| T1.1 | | | | `<comando>` | TODO |
| T1.2 | | | | | TODO |

### EPIC-2 — <título>

| Task | Qué hace | Archivos | Criterio de aceptación (1:1) | Verificación | Estado |
|---|---|---|---|---|---|
| T2.1 | | | | | TODO |

## 5. Definición de DONE global

- Todas las tasks en `DONE`.
- Cero tasks bloqueadas sin hallazgo registrado en `docs/state/HALLAZGOS-YYYYMMDD.md`.
- Cero P0 de seguridad abiertos.

## 6. P0 de seguridad

| ID | Hallazgo | Origen (`AS-IS` / premortem / blueprint) | Estado |
|---|---|---|---|
| | | | |
