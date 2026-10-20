# BACKLOG-EPICS v2 — FEAT-SCOPEGATE-CLOUD-ARCHITECTURE

Paso 3 de `docs/METODOLOGIA-SWARM.md`. Premortem + refutación + backlog de diseño del ciclo 4.

- Blueprint: [`BLUEPRINT-v1.md`](BLUEPRINT-v1.md)
- Spec: [`../specs/FEAT-SCOPEGATE-CLOUD-ARCHITECTURE.md`](../specs/FEAT-SCOPEGATE-CLOUD-ARCHITECTURE.md)
- Fecha: 2026-10-19

## 0. El premortem falsificó la razón por la que se eligió el lease

El blueprint eligió la opción B (lease) **por disponibilidad**, con este argumento: «da disponibilidad sin
volver a distribuir secretos». Al intentar escribir la secuencia de fallo, el argumento se cae:

> Si la inyección ocurre **solo** en el cloud, un lease no permite inyectar nada cuando el cloud no
> está. Sin secreto local, el edge no puede completar la petición: **el lease no restaura disponibilidad,
> porque la disponibilidad depende del proxy, no del permiso.**

Es decir: el lease resuelve **autorización**, no **inyección**. Confundir las dos es el error que este
premortem tenía que encontrar, y lo encontró en el propio razonamiento del paso anterior.

**Consecuencias, que son el corazón de este documento:**

1. La disponibilidad se resuelve con **redundancia del proxy y presupuesto de error** (condición 1 del
   blueprint), no con leases.
2. Los leases sirven para acotar la **staleness de revocación** y para no depender de una llamada de
   autorización por petición. Eso los mantiene útiles, con otro propósito declarado.
3. La degradación local-first de `src/gateway/server.ts:214-219` sigue siendo el mecanismo de
   disponibilidad para los gateways **no migrados**, y deja de aplicar a los migrados: hay que decirlo
   explícitamente en lugar de suponerlo.

## 1. Premortem (10 roles)

El diseño se aprobó y salió mal. Por qué, por orden de probabilidad.

| # | Modo de fallo | Probabilidad | Impacto | Mitigación en el plan |
|---|---|---|---|---|
| 1 | Se documenta el lease como mecanismo de disponibilidad y nadie diseña la redundancia del proxy | **Alta** — el blueprint ya lo escribió así | **Alto**: se lanza un plano de datos sin plan de caída | T1.1 es el primer artefacto y es obligatorio antes de cerrar; el §0 deja la falsificación escrita |
| 2 | La redención por petición mete al cloud en la ruta crítica: +1 round trip por cada salida | Alta | Alto: latencia y coste; el presupuesto de error se consume solo | T1.2 admite **dos clases de lease**: one-shot y burst acotado (N usos, mismo TTL), con auditoría por uso |
| 3 | Un lease con N usos sin tope se convierte en capability reutilizable | Media | Alto: bypass del `max_ttl` fail-closed | T1.2 fija tope de usos por clase y expiración **server-side**; reuso fuera de tope = P0 |
| 4 | La KEK termina en el `FileStore` del cloud «porque era más simple» | Media | **Alto**: un compromiso del plano entrega todos los tenants | T1.3 y T1.6 la prohíben con esas palabras, y T1.6 exige la alternativa declarada |
| 5 | Alguien reintroduce un `vault.enc` en el edge «solo para el modo degradado» | Media | Alto: N copias otra vez, el problema que el ciclo existe para eliminar | T1.6 prohibición explícita; T1.5 declara qué **no** funciona sin egress |
| 6 | La migración de los pares 1:1 se hace de golpe y una caída del cloud detiene la flota | Media | Alto | T1.5 exige ≥2 fases con estado declarado de cada una |
| 7 | El TTL del lease se fija en 60 s sin mirar el `max_ttl` del tenant y puede **exceder** la capability que respalda | Media | Medio: autorización más larga que el permiso | T1.2: TTL = `min(60s, max_ttl del tenant, vida restante de la capability)` |
| 8 | La firma del lease reutiliza la clave Ed25519 de políticas, que vive mucho más | Baja | Medio: una clave de larga vida firmando boletos de 60 s | T1.2 deja la decisión de la clave explícita (pregunta 3 del blueprint, cerrada ahí) |
| 9 | El audit del camino nuevo se parte entre gateway y cloud y la cadena de hashes deja de ser única | Media | Alto: se pierde la propiedad que el repo presume | T1.4 incluye quién es dueño de la cadena en el camino nuevo |
| 10 | El ciclo se «cierra» con cinco secciones escritas pero sin los números de latencia/error | Media | Medio: queda un diseño no falsable sobre su propia viabilidad | T1.1 exige que el presupuesto de error esté **declarado o marcado como pendiente con dueño**, no omitido |

## 2. Refutaciones adversariales (5 roles)

| El plan afirmaba | Refutación | Resultado |
|---|---|---|
| El lease da disponibilidad | Falso si la inyección es central: sin cloud no hay secreto que inyectar (§0) | `aceptada` — se reescribe el propósito del lease |
| One-shot estricto es lo más seguro | Es lo más seguro y lo más caro: un round trip por salida, justo lo que A5 señala | `aceptada` — se admite burst acotado, con auditoría por uso |
| La KEK puede vivir en el cloud con cifrado en reposo | Cifrado en reposo no protege de un proceso comprometido que tenga la clave de descifrado en memoria | `aceptada` — T1.3 exige declarar custodia externa o derivación fuera del proceso |
| El modo degradado puede usar el vault local «temporalmente» | Es el estado que el ciclo quiere eliminar; llamarlo temporal no lo hace temporal | `rechazada como opción` — prohibición explícita en T1.6 |
| La staleness de revocación ≤ TTL del lease es un dato | Es una promesa que depende de que la purga de leases no leídos funcione | `aceptada parcialmente` — T1.2 exige la purga como parte del contrato |

## 3. Veredicto de los jueces (3)

- **Plan apto para ejecutar: sí**, con el propósito del lease **reescrito**: autorización acotada y
  staleness de revocación, **no** disponibilidad.
- **Cambios obligatorios**: T1.1 antes que nada; dos clases de lease con tope y auditoría; TTL por
  fórmula; KEK fuera del proceso y del `FileStore`; prohibiciones explícitas; migración en ≥2 fases.
- **P0 abiertos**: ninguno de seguridad de datos en este ciclo (no se toca código), pero **queda declarado
  un P0 de diseño**: reusar un lease fuera de tope o transportar material secreto en él.
- **Condición de honestidad**: si un artefacto de diseño no puede declarar su número (latencia, error
  budget), se marca `PENDIENTE: <dueño>` y no se omite. Un hueco declarado es aceptable; un hueco
  silencioso, no.

## 4. EPICS y Tasks — artefactos de diseño, no código

Todos los artefactos de estas tasks se materializan en
[`DISENO-SCOPEGATE-CLOUD.md`](DISENO-SCOPEGATE-CLOUD.md): una sección por task, en el orden T1.1 → T1.6.

### 4.1 EPIC-1 — El camino de datos (va primero)

| Task | Qué produce | Criterio de aceptación (1:1) | Verificación | Estado |
|---|---|---|---|---|
| T1.1 | § «El cloud en la ruta de datos» | Declara latencia añadida esperada, presupuesto de error, SLO y **mecanismo de redundancia del proxy**; cada número declarado o `PENDIENTE: dueño` | `grep -c 'latencia\|error budget\|SLO\|redundan'` ≥ 4 en la § y ningún número sin dueño |

### 4.2 EPIC-2 — Contrato y claves

| Task | Qué produce | Criterio de aceptación (1:1) | Verificación | Estado |
|---|---|---|---|---|
| T1.2 | § «Contrato del lease» | Dos clases (one-shot, burst con tope N), campos `{id, agente, audiencia, expiración, usos}`, TTL por fórmula `min(60s, max_ttl, vida restante)`, expiración server-side, purga al revocar | la § contiene las dos clases, los cinco campos, la fórmula y la purga; y afirma que el lease **no** transporta material secreto |
| T1.3 | § «Jerarquía de claves» | KEK por tenant, DEK por secreto, rotación por nivel, custodia de la KEK declarada (externa o derivada fuera del proceso), y decisión sobre `@aws-sdk/client-kms` con su issue | nombra los dos niveles, una rotación por nivel, y una línea sobre custodia que no sea «en el cloud en claro» |

### 4.3 EPIC-3 — Frontera, modos y prohibiciones

| Task | Qué produce | Criterio de aceptación (1:1) | Verificación | Estado |
|---|---|---|---|---|
| T1.4 | § «Frontera: qué no cruza» + dueño de la cadena de audit | Tabla de ≥5 filas que incluya: valor del secreto, `master.key`, blob del vault, KEK, ids de capability de otro tenant; y una línea sobre quién firma/encadena el audit en el camino nuevo | la tabla tiene las cinco filas y la § nombra al dueño del audit |
| T1.5 | § «Modos y transición» | ≥2 fases; estado declarado de cada una; qué **no** funciona sin egress; relación con el local-first de `server.ts:214-219` | la § lista las fases y una fila explícita de «sin egress no funciona: …» |
| T1.6 | § «Prohibiciones» | Cada prohibición con su razón: réplica de `vault.enc` en el edge, KEK en claro en proceso o `FileStore`, secreto dentro del lease, reuso de lease fuera de tope | las cuatro prohibiciones aparecen con su razón nombrada |

### 4.4 EPIC-4 — Cierre del ciclo de diseño

| Task | Qué produce | Criterio de aceptación (1:1) | Verificación | Estado |
|---|---|---|---|---|
| T2.1 | Confirmar que el ciclo es solo documental | Cero cambios en `src/` y `package.json` | `git status --porcelain \| grep -E '^.. (src/\|package\.json)'` → sin salida |

## 5. Definición de DONE global

- T1.1 a T1.6 y T2.1 en `DONE`.
- Ninguna sección con un número de viabilidad omitido (declarado o `PENDIENTE: dueño`).
- Cero cambios en `src/` y `package.json`.
- Las cuatro preguntas del §6 del blueprint, respondidas dentro de los artefactos: TTL por fórmula (T1.2),
  redención por clase (T1.2), firma del lease (T1.2), modo demo fuera del camino nuevo (T1.5).

## 6. P0 de seguridad

Ninguno materializado (no hay código nuevo). Quedan **declarados** dos P0 de diseño que el próximo ciclo
de implementación debe tratar como bloqueantes: material secreto dentro de un lease, y reuso de un lease
fuera de su tope.
