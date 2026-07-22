---
name: False positive
about: PRISM flagged something that is not a real problem
title: "[FP] RULE-ID: short description"
labels: false-positive
---

**Rule id** (e.g. `SEC-ENV-VALUE` — see [docs/rules](../../tree/main/docs/rules)):

**The flagged code** (the actual line/snippet, anonymized if needed):

```
```

**Why it is not a real problem:**

**Context PRISM missed** (test fixture? template? gated elsewhere? domain convention?):

---
False positives are PRISM's highest-priority bug class — credibility is the primary design
constraint. Real flagged code (not a description of it) is what makes these fixable: every FP
rule refinement so far came from a concrete field sample.
