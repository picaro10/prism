# PRISM v0.9.0 — Import graph + circular dependency detection (TS/JS)

> **Estado:** Diseño aprobado, pendiente de plan de implementación
> **Fecha:** 2026-06-09 (Día 3)
> **Analizador afectado:** `structure` (nuevo check STR-012, apoyado en un motor de grafo nuevo)

## Contexto

"Structure profundo" tenía 4 candidatos. v0.8.0 tomó los dos sin grafo de imports
(god files + distribución). Esta versión construye el **grafo de imports TS/JS** —
la pieza que el SESSION_LOG marcó como "más superficie de FP, planear con cuidado" —
y lo usa para **un solo check**: detección de dependencias circulares.

Los **dead files** (la otra mitad, de mayor riesgo de FP por las heurísticas de entry
points) se difieren a v0.10.0. Razón: para detección de ciclos, un import mal resuelto
casi siempre *pierde* un ciclo (falso negativo seguro), nunca inventa uno (falso positivo).
Para dead files, un import no resuelto marca como "muerto" un archivo vivo (FP directo).
Validar el grafo primero con el check seguro (ciclos) antes de apoyar sobre él el check
peligroso (dead files) es el mismo escalonamiento que funcionó en v0.8.0.

## Alcance

- **Solo TS/JS.** Python/Go/Rust quedan para versiones futuras, cada uno con su resolver.
- **Construir el grafo de imports** (motor reutilizable).
- **STR-012 — Circular dependency.** Un check.
- **NO** dead files. **NO** alias/tsconfig resolution. **NO** otros lenguajes.

## Decisiones de diseño clave

### Solo aristas de valor (type-only ignoradas)
En TS, `import type {...}` se borra en compilación: un ciclo formado solo por imports
type-only es inofensivo en runtime (no causa el problema de módulos a medio-inicializar).
El grafo marca cada arista como type-only o de valor; **un ciclo se reporta solo si tiene
al menos una arista de valor**. Una arista es type-only únicamente si el statement es
`import type …` o `export type … from …`. El caso inline `import { type X, Y }` se trata
como arista de valor (conservador: `Y` es un valor real). Limitación aceptada: un
`import { type X }` (único miembro, type-only inline) se contabiliza como valor — caso
raro, y a lo sumo reporta un ciclo type-only ocasional, nunca pierde uno de valor.

### Resolución relative-only
`resolveSpecifier` resuelve **solo** imports relativos (`./`, `../`). Alias (`@/`, `paths`
de tsconfig) y bare specifiers (`react`, `node:fs`) → externos → sin arista.
**Consecuencia:** un ciclo que pasa exclusivamente por imports con alias se pierde (falso
negativo). Deliberado: parsear tsconfig (`extends`, JSON5, `baseUrl`/`paths`) es superficie
de FP y complejidad; y no-resolver solo pierde ciclos (seguro), nunca inventa (peligroso).
v0.10.0 puede añadir resolución de alias si el testing real muestra que perdemos ciclos
relevantes.

## Arquitectura

### Motor — `src/utils/import-graph.ts` (helpers puros, sin I/O salvo el reader inyectado)

```ts
export interface ImportEdge {
  specifier: string;   // el string literal del import, tal cual
  typeOnly: boolean;   // true si el statement es `import type` / `export type`
}

/** Extrae todos los imports de un archivo TS/JS, marcando los type-only. */
export function extractImports(content: string): ImportEdge[]

/**
 * Resuelve un specifier relativo a una ruta del proyecto existente, o null.
 * Solo resuelve imports relativos (./ y ../). Bare specifiers y alias → null.
 * `fileSet` es el conjunto de rutas del proyecto (para verificar existencia).
 */
export function resolveSpecifier(
  importerPath: string,
  specifier: string,
  fileSet: Set<string>,
): string | null

/**
 * Construye el grafo de imports de valor entre archivos fuente TS/JS.
 * Solo nodos de contexto `source`. Solo aristas de valor resueltas a archivos del proyecto.
 */
export async function buildImportGraph(
  files: string[],
  readFile: (path: string) => Promise<string>,
): Promise<Map<string, Set<string>>>

/**
 * Encuentra ciclos (componentes fuertemente conexos de tamaño >1, o self-loops)
 * vía Tarjan. Devuelve cada ciclo como una lista ordenada de archivos.
 */
export function findCycles(graph: Map<string, Set<string>>): string[][]
```

#### `extractImports`
Reusa y extiende el patrón del regex de `detectNoSutImport` (tests.ts). Reconoce:
- `import x from '…'`, `import {…} from '…'`, `import * as x from '…'`, `import '…'`
- `export {…} from '…'`, `export * from '…'`
- `require('…')`
- dynamic `import('…')` con string literal (un `import(variable)` no aporta arista)

`typeOnly`: true si el statement empieza con `import type` o `export type`. Para detectarlo
de forma robusta, la extracción debe operar por-statement (no solo por-specifier), de modo
de saber si la palabra `type` precede al binding. Implementación: una pasada que captura,
por cada match de import/export, el segmento del statement para inspeccionar `type`.

#### `resolveSpecifier`
Solo si `specifier` empieza con `./` o `../`:
1. Calcular la ruta candidata: `join(dirname(importerPath), specifier)` normalizada.
2. Reescritura TS: si termina en `.js`/`.jsx`/`.mjs`/`.cjs`, probar también la variante `.ts`/`.tsx`/`.mts`/`.cts`.
3. Probar en orden contra `fileSet`: ruta exacta; `+ .ts/.tsx/.js/.jsx/.mjs/.cts/.mts`; `+ /index.{ts,tsx,js,jsx,mjs}`.
4. Primer match que exista en `fileSet` → devolver esa ruta. Si ninguno → `null`.

Bare specifiers (no empiezan con `.`) y alias → `null` (externos, sin arista).

#### `buildImportGraph`
Para cada archivo de `files` que sea TS/JS (`.ts/.tsx/.js/.jsx/.mjs`) y contexto `source`
(`classifyFile === 'source'`): leer contenido (try/catch, skip en error), `extractImports`,
filtrar aristas type-only, resolver cada specifier de valor; si resuelve a un archivo del
proyecto, agregar arista `importer → target`. Nodos sin aristas igual existen en el grafo
(para que Tarjan los visite, aunque no formen ciclos).

#### `findCycles`
Tarjan SCC. Cada SCC de tamaño ≥2 es un ciclo. Un self-loop (`a → a`) también es ciclo
(archivo que se importa a sí mismo — raro pero real). Devolver cada ciclo como lista de
archivos en orden de descubrimiento. Ciclos deduplicados (cada SCC una vez).

### Integración en `StructureAnalyzer`

El motor vive en `import-graph.ts`. `StructureAnalyzer.analyze` lo invoca tras los checks
existentes (incluido STR-011) y emite `STR-012`. Patrón idéntico a god files.

## Check STR-012 — Circular dependency

- Un finding por ciclo detectado.
- Severidad **medium**.
- Forma:

```ts
{
  id: 'STR-012',
  category: 'structure',
  severity: 'medium',
  title: `Circular dependency (${cycle.length} files)`,
  description: `Circular import chain: ${chain}. Circular dependencies can cause partially-initialized modules at runtime and make the code harder to reason about.`,
  // chain = [...cycle, cycle[0]].join(' → ')
  suggestion: 'Break the cycle by extracting shared code into a separate module, or invert one dependency.',
  meta: { cycle },
}
```

- **Cap de findings**: máximo 20. Si hay más, emitir los primeros 20 y añadir nota al
  summary `"N more circular dependencies"` (sin cap silencioso).
- **Scoring**: `−0.5` por ciclo, topado en `−2.0` total para el check.

## Summary

Si `fileCount > 0` y se construyó el grafo, añadir al summary del structure analyzer:
- `"no circular dependencies"` si limpio, o
- `"N circular dependencies"` (+ `"M more"` si hubo overflow del cap).

## Guardas anti-FP

- Solo archivos TS/JS de contexto `source` son nodos (excluye vendor/generated/fixture/test/docs).
- Aristas type-only excluidas del grafo (solo ciclos con valor real).
- Un specifier solo produce arista si resuelve a un archivo que **existe en el set del proyecto**.
- Imports externos/no resolubles → sin arista (no inventan ciclos).
- `import(variable)` dinámico no literal → ignorado (no aporta arista falsa).

## Testing

### Unitarios (`tests/utils/import-graph.test.ts`)
- `extractImports`: named/default/namespace/side-effect import; `export … from`; `require`;
  dynamic `import('x')`; `import(variable)` → no specifier; `import type {…}` → typeOnly true;
  `import { type X, Y }` → typeOnly false (arista de valor); comentarios no rompen.
- `resolveSpecifier`: `./x` → `./x.ts`; `./x` → `./x/index.ts`; `../a/b` correcto;
  `./x.js` → `./x.ts` (reescritura); bare `react` → null; alias `@/x` → null;
  specifier que no existe en fileSet → null.
- `findCycles`: grafo acíclico → `[]`; `a→b→a` → un ciclo; `a→b→c→a` → un ciclo de 3;
  self-loop `a→a` → un ciclo; dos componentes, uno cíclico → un ciclo; nodos sin aristas → `[]`.

### Integración (`tests/analyzers/structure.test.ts`)
`ProjectScan` sintético + `FileReader` que devuelve contenidos con imports reales:
- Dos archivos que se importan mutuamente (valor) → un STR-012 con la cadena correcta.
- Ciclo formado solo por `import type` → **NINGÚN** STR-012.
- Archivos en `node_modules`/vendor que formarían ciclo → ignorados (no son nodos).
- Cap: 25 ciclos → 20 findings + nota de overflow en summary.
- Sin ciclos → summary contiene "no circular dependencies", sin findings STR-012.

## Fuera de alcance (explícito)

- Dead files (archivos sin importar) → v0.10.0.
- Resolución de alias / parsing de tsconfig `paths`/`baseUrl`.
- Python, Go, Rust.
- Detección type-only a nivel de miembro inline (`import { type X }` único miembro).
