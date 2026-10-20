# FEAT-SCOPEGATE-CLOUD-ARCHITECTURE — especificación

Paso 1.1 de `docs/METODOLOGIA-SWARM.md`. Ciclo 4.

- AS-IS de origen: [`../state/AS-IS-20261019.md`](../state/AS-IS-20261019.md) §8 (ampliación de hoy)
- Tipo: `feature` (arquitectura)
- Prioridad: `P1`

## 1. Problema

El brief del ciclo pedía «diseñar ScopeGate Cloud como servicio centralizado y multitenant, eliminando
el sidecar por agente». Medido, el diagnóstico es otro, y conviene escribirlo antes de diseñar:

**El plano de control ya existe.** `src/cloud/server` tiene políticas, aprobaciones, revocaciones,
capabilities, claves Ed25519 para firmar políticas, SSO, billing, alertas y persistencia
`FileStore`/`PostgresStore`. Los gateways ya se enrolan, sincronizan políticas, exportan audit y
consultan un checkpoint de revocación fail-closed.

**Lo que no existe es la custodia central del material secreto.** El vault es local por despliegue
(`vault.enc`, AES-256-GCM, master key local) y la inyección de credenciales ocurre en cada gateway con
**su** vault. Con la topología real —servicios emparejados **1:1 worker ↔ gateway**
(`SG_WORKER_DOMAIN`), no sidecar por agente— eso significa **N copias de los secretos de producción y N
radios de explosión**.

El problema, entonces, no es «no hay control plane»: es que **el secreto y la inyección están
distribuidos**. Ese es el alcance real de esta especificación.

## 2. Los cuatro pilares, contra el estado medido

| Pilar del brief | Estado real | Qué introduce este `FEAT` |
|---|---|---|
| **(a)** Bóveda central de credenciales maestras | **no existe**: vault local por gateway | Definir jerarquía de claves por tenant (KEK/DEK), custodia central y qué nunca sale de ella |
| **(b)** Capabilities con TTL estricto | **existe y es fail-closed**: `max_ttl` recorta todo grant, grants one-shot, minter renueva al 80% | Extender la garantía al camino central sin degradarla (defensa en profundidad, no sustitución) |
| **(c)** Cero texto plano en agentes | **ya se cumple por diseño**: el agente recibe capabilities, no secretos; `envScrub` borra secretos de `process.env`; `deny` globs bloquean `printenv`, `vault.enc`, `master.key` | Endurecerlo: en el modelo central el **gateway tampoco** ve el secreto |
| **(d)** Egress central con inyección en vuelo | **no existe**: cada gateway inyecta localmente | Definir el proxy de egress central: valida capability, inyecta, entrega respuesta, sin que el secreto toque al consumidor |

## 3. Límites técnicos

- **Dentro del alcance**: la especificación. Jerarquía de claves, contrato del egress central, modelo de
  aislamiento por tenant, política de indisponibilidad, y el camino de migración desde el modelo actual.
- **Fuera del alcance**: implementar. Este ciclo es Paso 1.1: un documento. El código va en su propio
  ciclo con su backlog.
- **Fuera de alcance también**: cambiar los **21 tools** `scopegate_*` (contrato congelado en
  `src/gateway/tools.ts`), romper el modo local/offline (self-host sin cloud debe seguir funcionando),
  y tocar el modo demo público (`SCOPEGATE_SEED_DEMO=1`).
- **Restricciones del repo que el diseño no puede violar**:
  - Sin dependencias de runtime nuevas sin issue previo.
  - Invariantes: política propuesta por agente no surte efecto sin revisión humana; `deny` globs y
    `max_ttl` fail-closed; toda acción privilegiada auditada.
  - Ningún valor de secreto en el repo, ni en config, ni en argv, ni en logs, ni en fixtures. Config solo
    con `secretRef`.
  - Los tests nunca tocan el `~/.scopegate` real (`useTempHome()`).

## 4. Requisitos

| ID | Requisito | Tipo |
|---|---|---|
| R1 | La jerarquía de claves se define explícitamente: clave maestra por **tenant**, clave de datos por **agente o por secreto**, y rotación de ambas sin re-cifrar todo el vault | funcional |
| R2 | Un secreto **nunca** viaja al gateway ni al agente: el egress central inyecta en vuelo y devuelve solo la respuesta | funcional |
| R3 | La capability sigue acotada por `max_ttl` y sigue siendo one-shot/TTL por construcción; el camino central **no** relaja ninguno de los dos límites | no funcional |
| R4 | Se define la política de indisponibilidad del plano central: qué pasa cuando el egress no está y cómo se preserva fail-closed sin convertir el cloud en caída total de la flota | funcional |
| R5 | El aislamiento entre tenants es verificable: una capability de un tenant no puede resolver una ruta de otro, ni por id, ni por política, ni por audit | funcional |
| R6 | Existe un camino de migración desde el modelo 1:1 actual que no obliga a un corte simultáneo de la flota | no funcional |
| R7 | El audit central registra emisión, uso y revocación de cada capability con la misma cadena de hashes y firma que hoy | no funcional |

## 5. Criterios de aceptación

Un criterio por task del backlog futuro. Todos verificables por documento, comando o artefacto — ninguno
por «parece correcto».

| ID | Criterio | Cómo se verifica |
|---|---|---|
| AC1 | El documento define la jerarquía de claves con nombres, quién custodia cada nivel y cómo rota cada uno | el § de claves nombra los niveles y una rotación por nivel; `grep -c 'KEK\|DEK'` > 0 con definición de ambos |
| AC2 | El documento declara explícitamente **qué** devuelve el egress central y **qué nunca** atraviesa el borde | existe una tabla «nunca cruza el borde» con al menos: valor del secreto, `master.key`, contenido del vault |
| AC3 | `max_ttl` sigue siendo el techo efectivo en el camino central | el documento cita `src/policy/engine.ts` como fuente del techo y no propone un TTL alternativo |
| AC4 | Hay una política de indisponibilidad escrita, con su consecuencia en la flota y su reversión | el documento responde qué ocurre con el cloud caído y con un tenant caído, y ambas respuestas respetan fail-closed |
| AC5 | El aislamiento entre tenants es una afirmación falsable, no un adjetivo | el documento enumera los tres vectores (id, política, audit) y cómo se bloquea cada uno |
| AC6 | La migración no exige corte simultáneo | el documento describe al menos dos fases y qué funciona en cada una |
| AC7 | Nada del diseño introduce dependencias nuevas ni toca los 21 tools | `git diff --name-only` del ciclo no incluye `package.json` ni `src/gateway/tools.ts` |

## 6. Non-goals

- Implementar el egress central o la bóveda en este ciclo.
- Sustituir el plano de control que ya existe (`src/cloud/server`): se extiende, no se reescribe.
- Eliminar el vault local: el self-host sin cloud sigue siendo un modo válido del producto.
- Cambiar la topología 1:1 en producción: el diseño debe permitirla durante la transición.
- Rediseñar SSO, billing o alertas.

## 7. Riesgos conocidos antes de planificar

| Riesgo | Impacto | Mitigación propuesta |
|---|---|---|
| **El plano central se vuelve punto único de fallo.** Centralizar el egress convierte una caída del cloud en una caída de credenciales para toda la flota, y el invariante es fail-closed | **Alto** | R4 lo convierte en requisito de primer nivel, no en nota al pie. El diseño debe ofrecer degradación declarada (por ejemplo, leases de corta vida ya emitidos siguen valiendo hasta su TTL) sin abrir un bypass |
| Mover el secreto al cloud **empeora** el radio de explosión si el cloud se compromete | Alto | Jerarquía KEK/DEK por tenant (R1) + el borde que nunca cruza (R2/AC2): comprometer un tenant no entrega los demás |
| El diseño promete «cero texto plano» y el gateway sigue viéndolo en el camino de transición | Medio | AC2 obliga a declarar el estado por fase; no se puede afirmar el invariante donde no rige |
| Presión por implementar antes de tener el modelo de claves | Medio | El `FEAT` es plan-only; el código va a otro ciclo con backlog propio |
| Un TTL distinto en el camino central rompe la garantía existente | Medio | R3/AC3: el techo es el que ya existe, y se cita su fuente |

## 8. Preguntas abiertas para el Paso 2

1. **Trust boundary**: ¿el cloud custodia el material o solo autoriza y el gateway conserva el secreto?
   Las dos arquitecturas son defendibles y la elección cambia el modelo de amenaza completo. Este `FEAT`
   no la decide.
2. **Indisponibilidad**: ¿lease de corta vida pre-emitido, caché local acotada, o corte fail-closed total
   como hoy? Cada opción tiene un precio distinto de seguridad y de disponibilidad.
3. **`SCOPEGATE_SEED_DEMO=1`**: el servicio público corre con datos demo. ¿El diseño central debe
   soportarlo, o queda explícitamente fuera?
4. **Audit central vs audit local**: hoy el gateway exporta; si el egress central inyecta, el evento
   nace en el cloud. ¿Quién es dueño de la cadena de hashes en el camino nuevo?
