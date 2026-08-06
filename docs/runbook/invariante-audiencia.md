# Runbook — el invariante de audiencia (`audience: "org"`)

**Dueño: Luis Rosas (@luisrosasx).** Es quien aprueba cualquier cambio en el
conjunto de identidades declaradas de una instancia y quien decide si una
instancia puede empezar a servir a un segundo workspace. Si no está
disponible, el cambio **no se hace**: no hay suplente, porque no hay ninguna
comprobación automática que lo respalde (ver §3).

Anclas de código: `src/gateway/http.ts` (el invariante y su consecuencia),
`src/policy/grants.ts` → `GrantStore.coversCaller` (la línea que depende de
él), `src/policy/engine.ts` → `agentIdAccepted` (el predicado que decide qué
identidad se acepta). Prueba ejecutable: `tests/audiencia-invariante.test.ts`.

---

## 1. El invariante, en una frase

**Una instancia de gateway sirve exactamente un workspace.**

Esa frase no es una nota de despliegue: es la única frontera que tiene la
audiencia `"org"`. En el plano de política de ScopeGate **no existe la noción
de workspace**. `"org"` es un literal, y `coversCaller` lo resuelve a
`agentAccepted(id)`, que significa *"una identidad declarada en esta
instancia"* — nunca *"del mismo workspace"*.

Mientras una instancia de gateway sirve exactamente un workspace, los dos
conjuntos coinciden y `audience: "org"` se comporta como si dijera «este
workspace». Es una coincidencia de topología, no una garantía del modelo.

## 2. Qué se rompe el día que deje de ser cierto

Basta con que una sola instancia acepte identidades de dos workspaces —un
gateway compartido, un glob de `agents:` que abarque los dos, o el catch-all
`*` conviviendo con los ids de un segundo inquilino— para que **todo grant
vivo con `audience: "org"` quede utilizable por las identidades del otro
workspace**.

Y ocurre **en silencio**: no cambia una línea de código, no cambia el
`grants.json`, no se emite ningún evento de auditoría distinto. El match sigue
teniendo éxito porque nunca se afirmó nada sobre workspaces.

La reparación **no es editar la política**: una política no puede expresar una
frontera que el modelo de datos no tiene. Es el renombrado a
`workspace:<id>` más la guarda de arranque fail-closed (EPIC-49.2 / 49.3).

## 3. Lo que este runbook NO afirma

- **`agentIdAccepted` tampoco es una comprobación de workspace hoy.**
  `docker/bootstrap-prod.mjs` escribe en el conjunto de política de producción
  tres secciones: `nexgen-kimi`, `demo-agent` y el catch-all `*`. Con ese
  catch-all, el predicado responde **sí** a cualquier id presentado en
  `X-ScopeGate-Agent`.
- Lo que hoy mantiene los grants `org` dentro de un workspace es la
  **topología de despliegue** (una instancia, un inquilino) más el bearer
  `$SCOPEGATE_HTTP_TOKEN`. **No es el modelo de grants.**
- No hay ninguna guarda de arranque que verifique nada de esto. Hasta
  EPIC-49.3, el invariante lo sostiene una persona, no el proceso.

## 4. Procedimiento — antes de tocar el conjunto de identidades

Aplica a: añadir una sección a `agents:` en el `policies.yaml` de una
instancia; ampliar un glob de `agents:`; añadir una identidad en
`docker/bootstrap-prod.mjs`; o apuntar un segundo worker/workspace a un
gateway que ya está en uso.

1. Enumerar las identidades que la instancia aceptará después del cambio
   (incluido el catch-all `*` si está presente: acepta todo).
2. Responder por escrito: **¿pertenecen todas al mismo workspace?**
   - **Sí** → el invariante se mantiene. Se anota el cambio y se sigue.
   - **No** → **para**. El cambio necesita antes EPIC-49.2 (renombrado a
     `workspace:<id>`) y EPIC-49.3 (guarda de arranque fail-closed). No se
     mitiga con una política.
3. Inventariar los grants `org` vivos antes de tocar nada:

   ```bash
   jq '[.grants[] | select(.audience=="org")] | length' "$SCOPEGATE_DIR/grants.json"
   ```

   Si el paso 2 dio «no» y este número es > 0, cada uno de esos grants es una
   fuga en el momento del cambio.
4. Actualizar `tests/audiencia-invariante.test.ts`: la prueba fija el conjunto
   de identidades que declara el arranque de producción **a propósito**, para
   que una identidad nueva no entre sin que alguien la mire. Si la prueba
   falla, la respuesta correcta es el paso 2, no ajustar la expectativa.
