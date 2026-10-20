# METODOLOGIA-SWARM — protocolo de 11 pasos

Contrato de trabajo para cambios no triviales en `scopegate`. Define **qué debe existir en disco al
final de cada paso**; no define los checks en sí.

Regla base: **si el artefacto del paso no está en `docs/`, el paso no ocurrió.**

## Fases

- **Fase A — Diagnóstico y planificación (pasos 1-3).** Restricción estricta: no se modifica código
  de producto y no se commitea a la rama por defecto. Solo se escriben documentos.
- **Fase B — Ejecución y remediación autónoma (pasos 4-6).** Se ejecuta el backlog hasta DONE, se
  cazan los gaps que aparecen después de implementar y se planifica la remediación.
- **Fase C — Integración, QA y cierre (pasos 7-11).** Commit verificado, PR, reconciliación de ramas y
  suite E2E adversarial.

## Los 11 pasos

| # | Paso | Acción | Entregable |
|---|---|---|---|
| 1 | Diagnóstico AS-IS | Estado actual, últimos commits, arquitectura de módulos, despliegue | `docs/state/AS-IS-YYYYMMDD.md` |
| 1.1 | Definición de característica / fix | Límites técnicos, requisitos, criterios de aceptación derivados del AS-IS | `docs/specs/FEAT-<NOMBRE_TAREA>.md` |
| 2 | Planificación deliberativa (18 roles) | 5 propositores · 5 defensores · 5 adversarios · 3 jueces · 2 refinadores | `docs/plans/BLUEPRINT-v1.md` |
| 3 | Premortem y backlog refinado (18 roles) | 10 premortem · 5 refutadores · 3 jueces, luego remediación del plan | `docs/plans/BACKLOG-EPICS-v2.md` |
| 4 | Autorización y ejecución | Con `plan_first` deshabilitado, ejecutar todas las tasks hasta DONE | `BACKLOG-EPICS-v2.md` con todas las tasks en DONE |
| 4.1 | Bucle de continuidad | Re-ejecutar oleadas mientras queden tasks pendientes | — (cierra el paso 4) |
| 5 | Caza de gaps post-ejecución | Bugs, deuda técnica, bloqueos tras la implementación | `docs/state/HALLAZGOS-YYYYMMDD.md` |
| 6 | Planificación de remediación (10 roles) | 3 propositores · 2 defensores · 2 adversarios · 3 jueces | `docs/plans/BLUEPRINT-REMEDIACION.md` |
| 7 | Despliegue y confirmación | Commit verificado + PR según § Entrega | estado declarado en `SESION-SYNC.md` |
| 8 | Autorización continua | Confirmaciones de continuidad del usuario | — (bitácora en `SESION-SYNC.md`) |
| 9 | Exploración y documentación de sesión | Cambios, feats y bugs resueltos de toda la sesión | `docs/state/SESION-SYNC.md` |
| 10 | Reconciliación y merge | Ramas a `master`, diferencias reconciliadas | `SESION-SYNC.md` § Merge |
| 11 | Evals y QA E2E adversarial | E2E del repo + red-team + suite externa | `docs/qa/QA-E2E-COMPLETO-YYYYMMDD.md` |

## Reglas de ejecución

1. **Plan-First en pasos 1-3.** Nada de código, nada de commits a `master` (la rama por defecto de
   este repo; no `main`). El paso 4 no arranca sin autorización explícita del usuario. Las ramas de
   trabajo salen de `master` con prefijo `fix:` / `feat:` / `docs:` en el asunto.
2. **Bloqueantes P0 de seguridad.** En ScopeGate la regla del repo es literal: **ningún valor de
   secreto entra al repo** — ni en configuración, ni en argv, ni en logs, ni en tests, ni en
   fixtures, ni en respuestas de herramientas. Aplicado a SWARM: los artefactos de `docs/qa/` y
   `docs/state/` **nunca** llevan capabilities minteadas, tokens de acceso, contenido de vault, ni
   volcados de auditoría con material sensible. Un artefacto que lo haga se borra y se registra como
   **P0**. Configuración solo lleva nombres de `secretRef`.
3. **Invariantes de diseño que el paso 3 no puede aprobar romper**: una política propuesta por el
   agente nunca surte efecto sin revisión humana; los límites duros (`deny` globs, `max_ttl`) se
   mantienen fail-closed; toda acción privilegiada queda auditada. Un `BLUEPRINT` que afloje cualquiera
   de los tres se rechaza en el paso 2, no en el paso 5.
4. **Criterios 1:1.** Cada task del `BACKLOG-EPICS-v2.md` lleva exactamente un criterio de aceptación
   verificable. Sin comando o artefacto que lo pruebe, no es un criterio.
5. **Evidencia o UNKNOWN.** Ruta:línea, SHA, comando + exit code. Se prefiere `[SUPUESTO]` marcado
   dentro del archivo antes que una pregunta al humano.
6. **Un artefacto por paso y por corrida.** Las corridas se fechan (`YYYYMMDD`); nunca se sobrescribe
   el artefacto de una sesión anterior.

## Entrega — lo que el paso 7 no puede ignorar

Reglas del repo que el paso 7 obedece tal cual (están en `AGENTS.md` y `CONTRIBUTING.md`):

- **Todo en verde antes de un PR**: `npm run build`, `npx tsc --noEmit`, `npm test`, y los e2e
  autocontenidos (`e2e-client.mjs`, `e2e-init.mjs`, `e2e-oauth.mjs`, `e2e-vaultd.mjs`). CI además
  construye el Dockerfile de producción y hace smoke del `/health` de la imagen.
- **Los tests nunca tocan el `~/.scopegate` real**: `useTempHome()` de `tests/helpers.ts` (mkdtemp de
  `SCOPEGATE_HOME` + `vi.resetModules()`), importando los módulos de `src` de forma dinámica después.
  Un e2e del paso 11 que use el home real es un P0, no una comodidad.
- **Sin dependencias de runtime nuevas** sin issue previo. Si un blueprint las necesita, se abre el
  issue en el paso 3 y el backlog espera a que exista.
- Diff acotado y con asunto convencional; los tres e2e de producción (`e2e-prod.mjs`,
  `e2e-ecosystem-prod.mjs`, `e2e-landing-prod.mjs`) no corren en CI porque requieren los servicios
  Railway vivos: el paso 11 los ejecuta solo con autorización explícita y registra los servicios
  contra los que corrió.

## Nomenclatura

| Patrón | Dueño |
|---|---|
| `docs/state/AS-IS-YYYYMMDD.md` | paso 1 |
| `docs/specs/FEAT-<NOMBRE_TAREA>.md` | paso 1.1 |
| `docs/plans/BLUEPRINT-v1.md` | paso 2 |
| `docs/plans/BACKLOG-EPICS-v2.md` | paso 3 |
| `docs/state/HALLAZGOS-YYYYMMDD.md` | paso 5 |
| `docs/plans/BLUEPRINT-REMEDIACION.md` | paso 6 |
| `docs/state/SESION-SYNC.md` | pasos 9-10 |
| `docs/qa/QA-E2E-COMPLETO-YYYYMMDD.md` | paso 11 |

Plantillas en `docs/plans/SWARM-TEMPLATES/`. `<NOMBRE_TAREA>` va en MAYUSCULAS_CON_GUION_BAJO.

## Convivencia con la documentación existente

Este repo no tiene anillo `ops/`: **SWARM es el contrato de orquestación**, sin segundo sistema de
fases con el que competir. Lo que sí existe y no se toca:

| Documento | Rol | Relación con SWARM |
|---|---|---|
| `docs/agents/README.md` + guías 01-08 | Documentación **de uso** del producto, escrita para agentes que consumen ScopeGate | SWARM no la edita ni la duplica; es documentación de producto, no de proceso |
| `SKILL.md` | Resumen de protocolo para usar ScopeGate como skill | Ídem |
| `docs/ecosistema.md` | Mapa de los 5 repos del ecosistema y su despliegue | Fuente para el AS-IS; no se reescribe desde un blueprint |
| `docs/runbook/invariante-audiencia.md` | Runbook del invariante de audiencia | Referencia de los invariantes del paso 3 |
| `LEARNINGS.md` | Trampas ya pagadas del repo | Manda sobre cualquier blueprint |
| `CHANGELOG.md` | Historial de versiones | Lo actualiza el paso 7 |

Regla de convivencia: SWARM vive en `docs/state`, `docs/specs`, `docs/plans` y `docs/qa`, cuatro
subdirectorios nuevos. `docs/agents/` y `docs/runbook/` conservan su función y no se reorganizan para
acomodar el protocolo.

## Persistencia y versionado

`docs/` está versionado en este repo (11 archivos rastreados al 2026-10-19) y **no** está ignorado:
no hay allow-list que extender. `.ultracode/runs.sqlite` (base local de runs de agente) sí queda
ignorado: es estado de máquina, no entregable.

Versionable no es agregado: el paso 7 hace `git add` explícito de los artefactos de la sesión.
