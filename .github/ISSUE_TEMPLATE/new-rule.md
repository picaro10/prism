---
name: New rule proposal
about: Propose a new detection rule
title: "[rule] CATEGORY: short name"
labels: new-rule
---

**Category** (security / dependencies / tests / structure / docker / consistency / agentic):

**What it detects** (one sentence):

**Why it matters:**

**Vulnerable example:**

```
```

**Correct example** (the pattern that must NOT fire):

```
```

**Known false-positive traps** (what legitimate code could look like this?):

---
PRISM's bar for new rules: **high-signal and conservative**. A rule that finds one more real
issue but adds three false positives makes the whole report less trustworthy and will not be
accepted. See [CONTRIBUTING](../../blob/main/CONTRIBUTING.md) for the rule checklist.
