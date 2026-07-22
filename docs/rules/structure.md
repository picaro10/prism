# Structure rules (`STR-*`) — weight 1.0×

| ID | Severity | What it detects |
|---|---|---|
| `STR-001` | medium | Missing `README.md`. |
| `STR-002` | high | Missing `.gitignore`. |
| `STR-003` | medium | Source files scattered in the project root. |
| `STR-004` | low | Deeply nested files. |
| `STR-005` | low | Inconsistent file naming within a directory. |
| `STR-006` | medium | No linter/formatter configuration. |
| `STR-007` | high | TypeScript project without `tsconfig.json`. |
| `STR-008` | info | Empty directories. |
| `STR-009` | medium | Large project without a `src/` directory. |
| `STR-010` | medium | Large project without a test directory. |
| `STR-011` | tiered¹ | God file: >400 / >600 / >900 / >1500 LOC. |
| `STR-012` | medium | Circular import dependency (Tarjan SCC over the resolved import graph). |
| `STR-013` | low | Dead file: TS/JS source nothing reaches. |

¹ `STR-011` severity scales with size: low → medium → high → critical at each LOC tier.

## False-positive notes

- **`STR-012` only counts value imports.** `import type` vanishes at compile time and is
  excluded — a type-only cycle is not a runtime cycle.
- **`STR-013` looks hard before declaring death:** type-only imports, tsconfig aliases,
  `package.json` references, path strings in code/HTML/Dockerfiles/shell scripts, shebang
  entries, and convention entrypoints all count as reachability. If a tsconfig is unparseable
  the rule skips itself rather than guess.
- Empty directories kept as intentional markers are a legitimate `STR-008` suppression:

```json
{ "rule": "STR-008", "reason": "Phase-2 skill directories are intentional placeholders" }
```
