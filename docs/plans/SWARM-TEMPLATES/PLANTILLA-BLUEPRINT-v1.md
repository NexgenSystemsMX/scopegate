# BLUEPRINT v1 — <NOMBRE_TAREA>

Paso 2 de `docs/METODOLOGIA-SWARM.md`. Planificación deliberativa sobre la spec aprobada.

- Spec de origen: `docs/specs/FEAT-<NOMBRE_TAREA>.md`
- Fecha / sesión:

## 1. Opciones de arquitectura (5 propositores)

| Opción | Idea | Costo | Riesgo | Supuestos que necesita |
|---|---|---|---|---|
| A | | | | |
| B | | | | |
| C | | | | |

## 2. Defensa de cada opción (5 defensores)

Para cada opción, viabilidad y mantenibilidad: qué la sostiene y qué la degradaría en 6 meses.

## 3. Ataque adversarial (5 adversarios)

| Opción atacada | Vector de falla | GAP expuesto | Severidad |
|---|---|---|---|
| | | | |

> Cualquier vector que toque secretos, credenciales o datos de usuario se marca **P0** y condiciona
> la elección del ganador.

## 4. Veredicto de los jueces (3)

- Opción ganadora:
- Motivo en una frase:
- Condiciones que el ganador debe cumplir:
- Opciones descartadas y por qué:

## 5. Plan consolidado (2 refinadores)

Sustituye a la opción ganadora tal cual: es el ganador con las condiciones de los jueces aplicadas.

### 5.1 Fases de implementación

| Fase | Qué cambia | Archivos / módulos | Verificación |
|---|---|---|---|
| 1 | | | |

### 5.2 Orden de ejecución y dependencias

### 5.3 Rollback

Cómo se vuelve atrás si la fase 1 falla.

## 6. Preguntas abiertas

Las que el paso 3 (premortem) debe resolver antes de ejecutar.
