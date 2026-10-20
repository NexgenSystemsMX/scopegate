# DISEÑO — ScopeGate Cloud como plano de datos

Artefactos de diseño del ciclo SWARM 4, ejecutando las tasks T1.1–T1.6 de
[`BACKLOG-EPICS-v2.md`](BACKLOG-EPICS-v2.md). **No es implementación**: especifica lo que un ciclo
posterior de código tiene que construir.

Regla de este documento: **cada número de viabilidad se declara o se marca `PENDIENTE: <dueño>`.** Un
hueco declarado es aceptable; un hueco silencioso, no.

---

## 1. El cloud en la ruta de datos (T1.1)

### 1.1 Qué cambia de clase

Hoy el cloud es un **plano de gestión**: si se cae, el gateway sigue con política local firmada
(`src/gateway/server.ts:214-219`). En el modelo central pasa a ser **plano de datos**: cada petición de
salida de cada agente atraviesa el proxy central, que valida la capability e inyecta la credencial real.

Es un cambio de clase de sistema, no una optimización. Se declara para que nadie lo descubra en el
premortem del ciclo de implementación.

### 1.2 Presupuesto de latencia

| Componente | Presupuesto | Estado |
|---|---|---|
| Hop adicional al proxy (idempotente, sin re-ensamblado de cuerpo) | **+15 ms p50 / +40 ms p95** sobre el tiempo de la llamada al upstream | `PENDIENTE: banco de pruebas del proxy (ciclo de implementación)` — no hay proxy que medir; los valores son el techo aceptable que fija este diseño |
| Validación de capability + redención de lease | **≤ 5 ms p95** (lookup por clave, sin escaneo) | `PENDIENTE: banco de pruebas del proxy (ciclo de implementación)` |
| Inyección y reenvío | sin buffer: el proxy **no** reensambla cuerpos ni tramas SSE | requisito, no número |

Nota que viene del repo: el borde ya sabe lo que cuesta el buffering. La regla de este diseño es la misma
que la del gateway: **inyectar en vuelo y no leer el cuerpo.**

### 1.3 Presupuesto de error y SLO

| Dato | Valor |
|---|---|
| SLO del camino de datos | **99,9 %** de redenciones correctas en 30 días |
| Error budget resultante | **≈ 43 min/mes** de indisponibilidad tolerada |
| Estado del SLO | `PENDIENTE: producto` — 99,9 % es la propuesta de este diseño, no una decisión tomada |
| Qué consume el budget | caída del proxy, fallo de KMS, caída del store de revocaciones |

### 1.4 Redundancia del proxy (el mecanismo que **sí** da disponibilidad)

El premortem del paso 3 dejó escrito que el lease no da disponibilidad. Estos son los mecanismos que sí:

1. **≥ 2 instancias del proxy** detrás del balanceador, **sin estado propio**: el estado (capabilities,
   revocaciones, leases) vive en el store, no en el proceso.
2. **Sin sesiones pegajosas**: cualquier instancia puede redimir cualquier lease.
3. **Health check que saca la instancia del balanceo** en fallo, sin esperar al timeout del cliente.
4. **Fallo del store = deny** (fail-closed), con aviso; fallo de **una** instancia = reintento en otra, sin
   decisión nueva.
5. **N+1 como mínimo operativo**, no N+1 "si hay presupuesto": el `PENDIENTE: producto` del §1.3 aplica al
   SLO, no a la redundancia.
6. **Fallo de un solo tenant = deny para ese tenant, nada para los demás.** Si su KEK no está disponible
   (KMS niega) o su partición del store falla, se purgan sus leases y sus redenciones pasan a deny; los
   otros tenants siguen operando. El aislamiento del §4.2 no es solo de datos: también de fallo.

---

## 2. Contrato del lease (T1.2)

### 2.1 Forma

```
{
  "id":         "lse_<opaco>",      // identificador, no adivinable, sin significado
  "agente":     "<agentId>",        // quién puede redimirlo
  "audiencia":  "<upstream>",       // contra qué upstream sirve
  "expira":     "<ISO 8601 ms>",    // evaluado SIEMPRE server-side
  "usos":       1 | N               // one-shot o burst acotado
}
```

**El lease no transporta material secreto. No contiene el valor de ningún secreto, ni una referencia
descifrable a él, ni un token del upstream.** Es un boleto de redención: la inyección ocurre solo en el
cloud, y solo en el momento de redimir.

### 2.2 Dos clases

| Clase | Usos | Para qué | Coste |
|---|---|---|---|
| **one-shot** (defecto) | `usos: 1` | Cada petición de salida | Un round trip de autorización por petición |
| **burst** | `usos: N`, tope por política (propuesta: **N ≤ 10**) | Ráfagas de llamadas al mismo upstream en la misma capability | Menos round trips; más radio si el lease se filtra |

Ambas clases se auditan **por uso**: el evento de redención se registra con el `id` del lease, así un
burst no deja de ser trazable.

### 2.3 TTL

```
ttl_lease = min(60 s, max_ttl del tenant, vida restante de la capability que lo respalda)
```

Razón: una autorización no puede vivir más que el permiso que la sostiene. Fijar 60 s a secas podía
producir un lease que excede el `max_ttl` del tenant, que es exactamente lo que `max_ttl` fail-closed
existe para impedir (`src/policy/engine.ts:17,99`).

### 2.4 Reglas de redención

1. **Expiración server-side.** El reloj del cliente no cuenta.
2. **Redención atómica**: dos redenciones concurrentes del último uso no pueden ganar las dos.
3. **Purga al revocar**: revocar un agente purga todos sus leases no redimidos. La staleness de revocación
   queda acotada por `ttl_lease`.
4. **Reuso fuera de tope = P0.** No es un error de validación: es un incidente.
5. **Auditoría obligatoria**: cada redención produce evento con `lease id`, agente, audiencia, resultado.

---

## 3. Jerarquía de claves (T1.3)

| Nivel | Qué cifra | Vida | Rotación |
|---|---|---|---|
| **KEK del tenant** | Envuelve (wrap) las DEK de ese tenant | larga (propuesta: 12 meses) | `re-wrap` de las DEK; **no** re-cifra los secretos |
| **DEK del secreto** | El valor del secreto, AES-256-GCM | media (propuesta: 90 días) | re-cifra ese secreto; el resto no se toca |

**Custodia de la KEK — prohibido lo obvio:**

- **No** en claro en memoria del proceso del cloud.
- **No** en el `FileStore` ni en la tabla de Postgres del plano, en claro ni "cifrada con otra clave que
  también vive ahí" (eso es cifrado decorativo).

Opciones admitidas, en orden de preferencia:

1. **KMS externo** (envolver/desenvolver la KEK por tenant). Requiere `@aws-sdk/client-kms`, que **no** es
   dependencia hoy (`package.json` solo tiene `@aws-sdk/client-sts`) → **issue previo obligatorio**.
2. **Derivación fuera del proceso**: la KEK se compone al arrancar desde material que un operador provee
   fuera de banda y que el plano no persistes.

**Decisión: KMS externo (opción 1), aprobada por el usuario el 2026-10-19.** Queda como prerrequisito del
ciclo de implementación abrir el issue que añada `@aws-sdk/client-kms`, porque hoy `package.json` solo
tiene `@aws-sdk/client-sts`: sin issue previo, la regla del repo prohíbe la dependencia nueva. La opción 2
queda como plan B si el issue no se aprueba.

**Riesgo residual declarado**: con KMS accesible por el proceso comprometido, un atacante con control del
cloud descifra los tenants que ese KMS permita. La KEK por tenant **contiene** el radio, no lo elimina.

---

## 4. Frontera: qué no cruza, y quién es dueño del audit (T1.4)

### 4.1 Tabla de no-exportables

| Dato | ¿Cruza al edge/gateway? | ¿Cruza al agente? | Razón |
|---|---|---|---|
| Valor del secreto | **nunca** | **nunca** | Es el objetivo del ciclo: hoy el gateway lo tiene, y eso es lo que se elimina |
| `master.key` | **nunca** | **nunca** | Llave maestra local; su existencia en el nuevo modelo es un defecto |
| Blob del vault (`vault.enc`) | **nunca** | **nunca** | Idem: N copias es el problema que se resuelve |
| KEK del tenant | **nunca** | **nunca** | Solo el KMS la abre; el plano no la devuelve |
| Lease de otro tenant / ids de capability ajenos | **nunca** | **nunca** | Un id filtrado es un oráculo de existencia |
| Lease propio (id, audiencia, expira, usos) | sí | sí (si el agente lo pide) | Es un boleto, no un secreto |
| Decisión de política (allow/deny + hash) | sí | sí | Debe ser verificable por el consumidor |
| Evento de auditoría del uso | sí (firmado) | sí | Trazabilidad |

### 4.2 Matriz de amenazas

| Amenaza | Vector | Contención |
|---|---|---|
| Robo del vault | acceso al store del plano | KEK cifrada por KMS; sin KEK el blob es opaco |
| Robo de un lease | log, memoria del agente | Secreto no viaja en el lease; tope de usos; TTL corto; purga al revocar |
| Cruce entre tenants | id adivinado, política mal scopeada | Aislamiento por 3 vectores: id opaco, scope de política, filtro en el audit |
| Proxy comprometido | ejecución en una instancia | Instancias sin estado persistente; secreto solo en memoria durante la inyección; rotación de KEK/DEK |
| Manipulación del audit | escritura directa | Cadena de hashes + firma; verificación en lectura |
| Replay de una redención | reenvío del id | Expiración server-side + redención atómica + auditoría por uso |

### 4.3 Dueño de la cadena de audit en el camino nuevo

Hoy el gateway produce el evento y lo exporta. En el modelo central **el evento de inyección nace en el
cloud**; el gateway deja de ser el firmante de ese hecho. Decisión de este diseño:

- El **cloud** es dueño de la cadena de los eventos de redención e inyección, firmados con la identidad
  Ed25519 del plano (`src/cloud/server/keys.ts`).
- El **gateway** conserva la cadena de lo que sigue ocurriendo en local (decisiones de política, tools).
- Las dos cadenas se exportan y se verifican por separado; **no se concatenan**, porque tienen productores
  distintos y concatenarlas permitiría que un productor lavara eventos del otro.
- **Lectura de R7** («la misma cadena de hashes y firma que hoy»): se interpreta como *mismo formato y
  mismo tipo de firma* (hash-chain + Ed25519, verificable con el mismo código), **no** como una única
  cadena compartida. Si producto quería una sola cadena global, este diseño la contradice a propósito y
  la contradicción se resuelve antes de implementar, no después.

---

## 5. Modos y transición (T1.5)

| Fase | Qué hay | Qué funciona sin egress | Estado |
|---|---|---|---|
| **0 — hoy** | Gateway con `vault.enc` local; cloud como plano de gestión | **Todo**: política local firmada + vault local | producción |
| **1 — sombra** | Los gateways siguen inyectando en local; el plano central **observa** y emite leases que no se usan para inyectar | Todo, y con la misma latencia de hoy | a construir |
| **2 — migrado** | La inyección ocurre en el plano; el gateway **no tiene** vault | **Nada del camino de salida**: sin egress no hay credencial, y la respuesta es deny | a construir |

**Declaración explícita de la fase 2**: *sin egress no funciona: inyección de credenciales.* El agente
puede seguir razonando y leyendo, pero no puede autenticar contra ningún upstream.

**Lo que la fase 1 permite**: comparar decisiones del plano contra las del gateway **antes** de mover la
inyección, sin cambiar el comportamiento observable. Es la única forma de migrar 1:1 worker↔gateway sin un
corte simultáneo de la flota.

**Relación con `server.ts:214-219`**: el local-first sigue siendo válido en fases 0 y 1, y deja de aplicar
a los gateways migrados en la fase 2. Se dice acá en vez de suponerlo.

**Modo demo (`SCOPEGATE_SEED_DEMO=1`)**: fuera de este camino. El `scopegate` público sigue siendo demo con
datos falsos y **no** pasa a ser punto de entrada de la flota en este diseño.

---

## 6. Prohibiciones (T1.6)

| # | Prohibición | Razón |
|---|---|---|
| P1 | **Réplica de `vault.enc` en el edge «para el modo degradado»** | Es el estado que el ciclo elimina. Llamarlo temporal no lo hace temporal, y reintroduce N copias de los secretos de producción |
| P2 | **KEK en claro** en memoria del proceso o en el `FileStore`/Postgres del plano | Cifrado en reposo no protege de un proceso comprometido con la clave de descifrado en memoria; cifrar con otra clave que vive al lado es cifrado decorativo |
| P3 | **Material secreto dentro de un lease** | Convierte un boleto en una credencial distribuida: exactamente lo que el ciclo evita. Un lease que transporta un secreto es un `vault.enc` con TTL |
| P4 | **Reuso de un lease fuera de su tope** | Un lease reutilizable es una capability con otro nombre; anula la redención atómica y la staleness acotada de revocación |

Cada prohibición es **criterio de rechazo** en el ciclo de implementación: un PR que las introduzca no
necesita discusión de diseño, se rechaza.
