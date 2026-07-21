# PRISM v0.8.0 — Structure profundo (God files + distribución)

> **Estado:** Diseño aprobado, pendiente de plan de implementación
> **Fecha:** 2026-06-09 (Día 3)
> **Analizador afectado:** `structure` (extensión content-aware)

## Contexto

El `StructureAnalyzer` actual (`src/analyzers/structure.ts`) es 100% basado en rutas
— ni siquiera usa el `FileReader` que recibe (`_readFile`). Todos sus checks (STR-001
a STR-010) miran nombres y árbol de directorios, nunca contenido.

"Structure profundo" era el candidato fuerte al 7º analizador en el SESSION_LOG, con la
advertencia explícita: *"Requiere parser de imports → más superficie de FP, planear con
cuidado."* De los 4 checks candidatos (god files, dead files, dependencias circulares,
distribución de tamaño), esta versión toma **solo los dos que NO necesitan grafo de
imports** — manteniendo la credibilidad ~96% recién recuperada en v0.7.1 sin introducir
la superficie de FP del resolver. El grafo de imports (dead files + ciclos) queda para
una v0.9.0 con su propio diseño.

## Alcance (Opción A)

- **God files** (`STR-011`): detección de archivos fuente demasiado grandes por LOC.
- **Distribución de tamaño**: métricas en el `summary`, **sin findings nuevos**.
- **NO** se construye grafo de imports. **NO** dead files. **NO** dependencias circulares.

El `StructureAnalyzer` pasa a ser content-aware: lee el contenido de los archivos fuente
para contar líneas.

## Arquitectura

### Módulo de helpers puros — `src/utils/loc.ts`

Funciones sin estado, testeables en aislamiento (mismo patrón que `detectNoSutImport` y
`findPythonDecorativeTests`):

```ts
/** Cuenta líneas totales del archivo. */
export function countLoc(content: string): number

/** Clasifica un archivo por su LOC en un tramo de severidad, o null si no aplica. */
export function classifyGodFile(loc: number): 'high' | 'medium' | 'low' | 'info' | null

/** Métricas de distribución sobre los archivos fuente medidos. */
export function computeSizeMetrics(
  measured: { path: string; loc: number }[],
): {
  totalLoc: number;
  fileCount: number;
  median: number;
  largest: { path: string; loc: number } | null;
  top5Pct: number; // % del LOC total concentrado en los 5 archivos más grandes
}
```

`countLoc`: `content.split('\n').length`. Transparente y reproducible (decisión "(a)
líneas totales", no líneas significativas — el detector se mantiene tonto y honesto, igual
que la reescritura de TST-011 a nivel de archivo).

`classifyGodFile` (tramos aprobados, sin `critical`):
- `loc > 1500` → `high`
- `loc > 900` → `medium`
- `loc > 600` → `low`
- `loc > 400` → `info`
- en otro caso → `null`

`computeSizeMetrics`:
- `median`: mediana de LOC (manejar listas par e impar).
- `top5Pct`: `sum(top 5 por LOC) / totalLoc * 100`, redondeado. `0` si `totalLoc === 0`.
- `largest`: el archivo de mayor LOC, o `null` si la lista está vacía.

### Integración en `StructureAnalyzer.analyze`

El analizador itera los archivos fuente, lee contenido y mide LOC. Se añade tras los
checks existentes, sin tocarlos.

## Guardas anti-FP (núcleo de credibilidad)

Un archivo se **mide** solo si cumple TODO:

1. **Extensión fuente**: `.ts`, `.tsx`, `.js`, `.jsx`, `.mjs`, `.py`, `.rs`, `.go`, `.java`.
2. **Contexto `source`**: `classifyFile(path) === 'source'`. Esto excluye `generated`,
   `vendor`, `fixture`, `template`, `documentation`, `config-template` y `test`.
   (`classifyFile` es path-based — no requiere contenido.) Un god file relevante es
   código de producción; un test o un archivo generado grande no es el smell que buscamos.
3. **No minificado**: si `content.length / max(lineCount, 1) > 500` (promedio de chars por
   línea > 500), el archivo no fue escrito a mano (bundle/datos) → se salta.
4. **Lectura sin error**: si `readFile` lanza, se salta en silencio (patrón de `tests.ts`).

## God files — política de findings (`STR-011`)

- **info (`>400`)**: NO genera finding. Solo cuenta en las métricas de distribución.
- **low (`>600`), medium (`>900`), high (`>1500`)**: un finding `STR-011` por archivo.
- Findings ordenados por LOC descendente.
- **Cap de ruido**: máximo **25** findings individuales. Si hay más archivos que superan
  el umbral de finding (`>600`), se emiten los 25 más grandes y se añade una nota al
  `summary`: `"N archivos más superan 600 LOC"`. **Sin cap silencioso** (principio del log:
  "No silent caps").

Forma de cada finding:

```ts
{
  id: 'STR-011',
  category: 'structure',
  severity: 'high' | 'medium' | 'low',  // = tramo de classifyGodFile
  title: `God file: ${path} (${loc} LOC)`,
  description: `${path} tiene ${loc} líneas. Los archivos grandes concentran responsabilidades, dificultan el test y el review.`,
  file: path,
  suggestion: 'Considerá dividir este archivo por responsabilidad en módulos más chicos.',
  meta: { loc, tier },
}
```

## Distribución (summary, sin findings)

Se concatena al `summary` del resultado una línea con las métricas de `computeSizeMetrics`,
por ejemplo:

```
12.4k LOC · 142 archivos fuente · mediana 78 · mayor src/core/engine.ts (1450) · top-5 = 31% del código · 3 god files (1 high, 2 medium)
```

Las métricas alimentan la Fase 2 (capa LLM) con la foto numérica; la capa estática señala,
la inteligencia juzga. No se inventa un veredicto que solape con god files.

## Scoring

Deducción acumulada sobre el score de `structure`:
- cada god file `low` → `−0.2`
- cada god file `medium` → `−0.5`
- cada god file `high` → `−1.0`

**Cap total del check en `−3.0`**: la suma de deducciones por god files nunca resta más de
3 puntos, para que un repo con muchos archivos grandes no aniquile solo el score de
structure. (El score final sigue clampeado a `[0, 10]` por el analizador.)

Los findings `info` (`>400`) no afectan el score.

## Testing

### Unitarios (`tests/utils/loc.test.ts`)
- `countLoc`: archivo vacío, una línea, N líneas, con/sin newline final.
- `classifyGodFile`: valores frontera exactos (400, 401, 600, 601, 900, 901, 1500, 1501)
  y un valor chico → `null`.
- `computeSizeMetrics`: lista vacía (`largest: null`, `top5Pct: 0`), un archivo, mediana
  par e impar, concentración top-5 con >5 archivos.

### Integración (`tests/analyzers/structure.test.ts`)
`ProjectScan` sintético + `FileReader` falso que devuelve contenido con conteos de línea
controlados (patrón de los tests de TST-001 en v0.7.1):
- Archivo fuente de 1600 líneas → `STR-011` severity `high`.
- Archivos en tramos low/medium/high → tramos correctos y deducción de score esperada.
- Archivo de 450 líneas → NO genera finding (info), pero cuenta en métricas.
- **Exclusiones**: archivo grande en `node_modules`/vendor, en `__fixtures__`, generado, y
  un `*.test.ts` grande → NINGUNO genera `STR-011`.
- Minificado (una línea de 30k chars) → no se marca.
- Cap: 30 archivos >600 LOC → exactamente 25 findings + nota en summary.
- `summary` contiene la línea de distribución.

## Fuera de alcance (explícito)

- Grafo de imports / resolución de módulos.
- Dead files (archivos sin importar).
- Dependencias circulares.
- Líneas significativas (excluir comentarios/blancos) — se usa conteo total.
- Umbrales por lenguaje (un solo set de tramos para todos).

Todo esto es candidato a v0.9.0, que se diseñará por separado.
