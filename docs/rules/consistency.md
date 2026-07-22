# Consistency rules (`CON-*`) — weight 0.8×

| ID | Severity | What it detects |
|---|---|---|
| `CON-001` | low | Mixed file-naming conventions (kebab/snake/camel/pascal) within one language. |
| `CON-002` | low | Mixed natural language (Spanish + English identifiers) in the same file. |
| `CON-003` | low | Inconsistent indentation (tabs vs spaces) across the codebase. |

## False-positive notes

- `CON-002` measures *identifiers*, not comments or strings. Known open refinement: a domain
  vocabulary that is legitimately bilingual (e.g. Spanish business terms in an English codebase)
  can trip it. If your domain language is intentionally mixed, suppress with that reason:

```json
{ "rule": "CON-002", "reason": "Domain entities are Spanish by design; code verbs are English" }
```
