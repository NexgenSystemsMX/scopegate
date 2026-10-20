# BLUEPRINT v1 — FEAT-SCOPEGATE-CLOUD-ARCHITECTURE

Paso 2 de `docs/METODOLOGIA-SWARM.md`. Deliberación de 18 roles sobre
[`../specs/FEAT-SCOPEGATE-CLOUD-ARCHITECTURE.md`](../specs/FEAT-SCOPEGATE-CLOUD-ARCHITECTURE.md).

## 0. Precedentes del repo que la deliberación no puede ignorar

Antes de debatir se leyó cómo resuelve el repo, **hoy**, los dos dilemas que se le piden.

| Hecho | Evidencia | Consecuencia para el diseño |
|---|---|---|
| El gateway es **local-first**: «a dead control plane leaves the gateway running on local policy + the last signed team policy cache» | `src/gateway/server.ts:214-219` (EPIC-10) | «Fail-closed total» **contradice** el diseño documentado: el repo ya decidió cómo se degrada sin control plane |
| La revocación se comprueba **contra estado sincronizado localmente** (`cloud-revoked.json`) y es fail-closed al ejecutar | `src/gateway/server.ts:10-11` | El retraso de revocación ya existe y ya está aceptado: la pregunta es cuánta staleness tolera un lease |
| El minter cachea **en memoria**, nunca en disco, y renueva al 80% del TTL | `src/minter/*.ts:19-20,100` | Hay un precedente claro de «caché acotada y volátil» como mecanismo aceptable |
| `@aws-sdk/client-sts` ya es dependencia; **`@aws-sdk/client-kms` no** | `package.json` | Una KEK custodiada por KMS implica **dependencia nueva** → issue previo obligatorio |

## 1. Opciones para el dilema (a): caída del egress central (5 propositores)

| Opción | Mecanismo | Idea de diseño |
|---|---|---|
| **A** | Fail-closed total: sin egress no hay credencial | Máxima seguridad; la nube caída detiene la flota |
| **B** | **Lease one-shot pre-emitido**, TTL corto (≤ 60 s), redención única; agotados los leases, deny | El cloud pre-autoriza usos concretos; el boleto no es el secreto |
| **C** | Caché local **del secreto** cifrada, TTL corto | Disponibilidad alta; **reintroduce el material distribuido** que el `FEAT` quiere eliminar |
| **D** | Degradar a solo-deny tras N minutos sin egress, con aviso | Prolonga la operación, pero el «cuándo» es un número mágico |
| **E** | Leases renovables sin vencimiento mientras el agente esté autorizado | Cero fricción; convierte una autorización en permanente |

## 2. Defensa (5 defensores)

- **D1 — B**: es la única que no contradice nada de lo ya decidido: el repo cachea **decisiones firmadas**
  y estados de revocación, nunca secretos. Un lease es una decisión pre-firmada con vencimiento.
- **D2 — B**: acota la ventana de staleness de revocación a la vida del lease. Si el lease dura 60 s, la
  revocación tarda a lo sumo 60 s más de lo que ya tarda hoy por el checkpoint local.
- **D3 — D**: da una respuesta operativa explícita («la flota pasa a solo-deny») en vez de una caída
  silenciosa, y es compatible con A como estado final.
- **D4 — C**: es la única que mantiene la inyección local funcionando sin egress, y ya existe precedente
  de caché volátil en el minter.
- **D5 — A**: cualquier degradación es una superficie; el invariante dice fail-closed y punto.

## 3. Ataque (5 adversarios)

- **A1 — contra C**: es el caballo de Troya del ciclo. Un «caché local de secretos cifrada» es exactamente
  el `vault.enc` que este `FEAT` quiere sacar de los gateways: N copias otra vez, con un TTL como
  excusa. Reintroduce el problema que el ciclo existe para resolver.
- **A2 — contra B**: si el lease **transporta** el secreto, B es C disfrazado. La única forma de que B sea
  legítimo es que el lease sea un **boleto de redención** (id opaco + audiencia + expiración), y que la
  inyección ocurra solo en el cloud. El blueprint debe decirlo con esas palabras.
- **A3 — contra B y D**: el TTL del lease es una promesa sobre el reloj. Sin expiración evaluada
  **server-side** y sin redención única, un lease es una capability reutilizable — y el repo tiene
  `max_ttl` fail-closed precisamente porque eso importa.
- **A4 — contra A**: contradice `server.ts:214-219`. Adoptar A obligaría a **cambiar** el comportamiento
  documentado del gateway (hoy sobrevive a un control plane muerto), y eso es una decisión de producto,
  no un detalle de arquitectura.
- **A5 — transversal, y es el ataque más fuerte**: toda esta deliberación asume que «el cloud» deja de ser
  un plano de gestión y pasa a ser **plano de datos**, en la ruta de cada petición de salida. Eso cambia
  la clase de sistema: pasa de algo que tolera caerse a algo que no. Ninguna opción lo discute, y hay que
  decidirlo antes de elegir mecanismo de resiliencia.

## 4. Veredicto de los jueces (3)

- **Dilema (a) — ganador: B, con D como estado final del agotamiento.**
  Leases **one-shot de redención**, TTL ≤ 60 s, sin material secreto dentro, redención única evaluada
  server-side; agotados los leases y sin egress, la flota pasa a **solo-deny** con aviso.
- **Motivo en una frase**: es la única opción que da disponibilidad sin volver a distribuir secretos y sin
  contradecir el local-first ya documentado.
- **Dilema (b) — ganador: jerarquía KEK por tenant / DEK por secreto, con tabla de no-exportables.**
  Sin cambios respecto del `FEAT`; la deliberación añade la **condición** de que la KEK no viva en claro
  en el proceso ni en el `FileStore` del cloud (ver condiciones).
- **Condiciones**:
  1. **A5 se eleva a requisito**: el `FEAT` (o su sucesor) debe declarar explícitamente que el cloud pasa
     a estar en el camino de datos y qué implica (latencia, presupuesto de error, SLO). Sin eso, el resto
     del diseño está construido sobre una decisión no tomada.
  2. **A2**: el lease no transporta secretos. Se define como `{id opaco, agente, audiencia, expiración,
     uso: único}` y se documenta que su redención ocurre solo en el cloud.
  3. **A3**: expiración server-side y redención única; un lease reusado es un P0.
  4. **C queda prohibida explícitamente** en el `FEAT` (prohibir es más fuerte que no elegir: evita que
     reaparezca «por disponibilidad» en el premortem).
  5. **Dependencia nueva visible**: si la KEK se custodia con `@aws-sdk/client-kms`, va con su issue
     previo (regla del repo). Si no, la KEK se deriva de material operado fuera del cloud y esa decisión
     se documenta.
  6. **Revocación**: al revocar, los leases no redimidos se purgan; el estado de revocación sigue
     viajando como hoy (`cloud-revoked.json`), con la staleness acotada por el TTL del lease.

## 5. Plan consolidado (2 refinadores)

Este ciclo **no implementa**: consolida decisiones de arquitectura. Lo que se produce:

| # | Artefacto de diseño | Qué debe resolver | Verificación del cierre |
|---|---|---|---|
| 1 | § «El cloud en la ruta de datos» | A5: latencia, presupuesto de error, SLO, qué pasa con la ruta caliente | existe la § y nombra los cuatro puntos |
| 2 | § «Contrato del lease» | forma del lease, TTL máximo, redención única, purga por revocación | el contrato lista los cinco campos y prohíbe material secreto |
| 3 | § «Jerarquía de claves» | KEK por tenant, DEK por secreto, rotación por nivel, dónde vive cada clave | nombra los niveles y una rotación por nivel; declara si hay KMS |
| 4 | § «Frontera: qué no cruza» | tabla de no-exportables | incluye al menos: valor del secreto, `master.key`, blob del vault, KEK, ids de capability de otro tenant |
| 5 | § «Modos y transición» | local-first intacto, migración en ≥2 fases, qué funciona sin egress | describe dos fases y el estado resultante de cada una |

### 5.1 Matriz de decisión (resumen ejecutable)

| Pregunta | Decisión | Razón |
|---|---|---|
| ¿Caché local de secretos? | **No, nunca** | Reintroduce el problema del ciclo (A1) |
| ¿Lease con TTL? | **Sí, ≤ 60 s, one-shot, sin secreto** | Acota staleness de revocación y evita distribución (B, D2) |
| ¿Cloud caído? | Agotar leases y pasar a **solo-deny** con aviso | Compatible con local-first, sin bypass (D) |
| ¿Fail-closed total? | **No** como comportamiento de la flota | Contradice `server.ts:214-219`; sería cambio de producto |
| ¿KEK/DEK? | **Sí, por tenant / por secreto** | Contención del radio de explosión |
| ¿KMS externo? | **Decisión pendiente del usuario** (dependencia nueva) | Regla del repo: issue previo |

### 5.2 Riesgos que sobreviven al ataque

| Riesgo | Estado |
|---|---|
| El cloud pasa a plano de datos y no se declaró el presupuesto de error | **Abierto por diseño**: condición 1 lo convierte en el primer artefacto del siguiente ciclo |
| Compromiso del cloud + acceso a KMS entrega todos los tenants | **Mitigado parcialmente**: KEK por tenant; el riesgo residual se documenta, no se elimina |
| Staleness de revocación acotada por el TTL del lease | **Aceptado y medido**: ≤ 60 s sobre la staleness que ya existe |
| Reaparición de la caché de secretos «por disponibilidad» | **Cerrado**: prohibición explícita (condición 4) |
| La dependencia de KMS se cuela sin issue | **Cerrado**: condición 5 y AC correspondiente en el `FEAT` |

## 6. Preguntas abiertas para el Paso 3

1. ¿60 s es el TTL correcto, o debe derivarse de `max_ttl` del tenant para que un lease nunca viva más que
   la capability que respalda?
2. ¿El lease se redime una vez por **petición** o por **ráfaga**? Cambia el volumen de llamadas al cloud y
   por tanto el dimensionamiento del nuevo camino de datos.
3. ¿Quién firma el lease: la misma identidad Ed25519 que firma políticas (`cloud/server/keys.ts`) o una
   clave distinta con vida más corta?
4. Si el cloud es plano de datos, ¿el `scopegate` público con `SCOPEGATE_SEED_DEMO=1` sigue siendo una
   demo o pasa a ser el punto de entrada de la flota? El `FEAT` lo dejó fuera; el premortem debe
   confirmar que sigue fuera.
