# Informe de SonarQube Community - Grupo SI26-G06

Generado el 2026-10-04 desde la API de SonarQube (http://localhost:9000). Cada fila es un analisis; la primera es la version base (`v-base`) y las siguientes, el codigo corregido.
Notas: A = mejor, E = peor. Security/Reliability/Maintainability = cantidad de problemas abiertos.

## mesa-ayuda-backend

| Fecha del analisis | Version | Security | Reliability | Maintainability | Hotspots | Lineas | Cobertura | Duplicacion |
|---|---|---|---|---|---|---|---|---|
| 2026-10-04T05:25:33+0000 | not provided | D (2) | D (1) | A (7) | 0 | 258 | 0.0% | 0.0% |
| 2026-10-04T20:07:31+0000 | parte6-corregida | A (0) | A (0) | A (8) | 0 | 303 | 0.0% | 0.0% |
| 2026-10-04T20:26:12+0000 | parte6-corregida | A (0) | A (0) | A (0) | 0 | 311 | 0.0% | 0.0% |

Quality Gate actual: **ERROR**
- Condicion que falla: `new_coverage` = 0.0 (umbral LT 80)

## mesa-ayuda-frontend

| Fecha del analisis | Version | Security | Reliability | Maintainability | Hotspots | Lineas | Cobertura | Duplicacion |
|---|---|---|---|---|---|---|---|---|
| 2026-10-04T05:30:14+0000 | not provided | E (1) | C (7) | A (3) | 0 | 416 | 0.0% | 0.0% |
| 2026-10-04T20:12:11+0000 | parte6-corregida | A (0) | C (7) | A (1) | 0 | 416 | 0.0% | 0.0% |

Quality Gate actual: **OK**

Limitacion de la edicion Community: no hace analisis de flujo de datos (taint analysis), por lo que no detecta inyecciones SQL ni XSS; ver Bearer, ZAP y las pruebas de ataque en `infra/pruebas/`.
