// ============================================================
// PRISM — Curated Semgrep taint rules
//
// Shipped embedded (not as loose YAML) so the tsup bundle carries them —
// no files-array/path-resolution fragility between dev (tsx) and dist.
// The analyzer materializes this string to a temp file at run time.
//
// Curation policy: few rules, high signal. Every rule targets a dataflow
// class PRISM's structural analyzers cannot see (taint from user input to a
// dangerous sink), carries CWE/OWASP metadata, a prism-severity, and a fix.
// The AI triage layer runs on top to kill the false positives taint
// analysis is famous for — precision comes from the pair, not the rule.
// ============================================================

export const SEMGREP_RULES_YAML = `rules:
  # ---------- JavaScript / TypeScript ----------
  - id: prism-sqli-tainted-query
    languages: [javascript, typescript]
    severity: ERROR
    mode: taint
    message: >-
      User-controlled input flows into a SQL query string. String-building a
      query from request data allows SQL injection.
    metadata:
      prism-severity: critical
      cwe: CWE-89
      owasp: "A03:2021 - Injection"
      fix: Use parameterized queries ($1/? placeholders) and pass values separately.
    pattern-sources:
      - pattern: req.query
      - pattern: req.body
      - pattern: req.params
      - pattern: req.headers
    pattern-sinks:
      - patterns:
          - pattern-either:
              - pattern: $DB.query($Q, ...)
              - pattern: $DB.execute($Q, ...)
              - pattern: $DB.raw($Q, ...)
          - focus-metavariable: $Q

  - id: prism-xss-tainted-response
    languages: [javascript, typescript]
    severity: ERROR
    mode: taint
    message: >-
      User-controlled input is written into an HTML response without
      sanitization — reflected XSS.
    metadata:
      prism-severity: high
      cwe: CWE-79
      owasp: "A03:2021 - Injection"
      fix: Escape output (or render through a template engine with auto-escaping); never concatenate request data into HTML.
    pattern-sources:
      - pattern: req.query
      - pattern: req.body
      - pattern: req.params
    pattern-sanitizers:
      - pattern: escapeHtml(...)
      - pattern: encodeURIComponent(...)
      - pattern: DOMPurify.sanitize(...)
    pattern-sinks:
      - patterns:
          - pattern-either:
              - pattern: $RES.send($OUT)
              - pattern: $RES.write($OUT)
          - focus-metavariable: $OUT
          - metavariable-pattern:
              metavariable: $RES
              patterns:
                - pattern-either:
                    - pattern: res
                    - pattern: response

  - id: prism-dom-xss-innerhtml
    languages: [javascript, typescript]
    severity: ERROR
    mode: taint
    message: >-
      URL-controlled data flows into innerHTML/outerHTML/document.write —
      DOM-based XSS.
    metadata:
      prism-severity: high
      cwe: CWE-79
      owasp: "A03:2021 - Injection"
      fix: Use textContent, or sanitize with DOMPurify before assigning HTML.
    pattern-sources:
      - pattern: location.search
      - pattern: location.hash
      - pattern: location.href
      - pattern: document.URL
      - pattern: document.referrer
    pattern-sanitizers:
      - pattern: DOMPurify.sanitize(...)
    pattern-sinks:
      - patterns:
          - pattern-either:
              - pattern: $EL.innerHTML = $HTML
              - pattern: $EL.outerHTML = $HTML
              - pattern: document.write($HTML)
          - focus-metavariable: $HTML

  - id: prism-ssrf-tainted-url
    languages: [javascript, typescript]
    severity: ERROR
    mode: taint
    message: >-
      User-controlled input is used as a request URL — server-side request
      forgery (SSRF). An attacker can point the server at internal services
      or cloud metadata endpoints.
    metadata:
      prism-severity: high
      cwe: CWE-918
      owasp: "A10:2021 - Server-Side Request Forgery"
      fix: Validate against an allowlist of hosts/schemes before fetching; never fetch a raw user-supplied URL.
    pattern-sources:
      - pattern: req.query
      - pattern: req.body
      - pattern: req.params
    pattern-sinks:
      - patterns:
          - pattern-either:
              - pattern: fetch($URL, ...)
              - pattern: axios.get($URL, ...)
              - pattern: axios.post($URL, ...)
              - pattern: axios($URL, ...)
              - pattern: http.get($URL, ...)
              - pattern: https.get($URL, ...)
          - focus-metavariable: $URL

  - id: prism-path-traversal-fs
    languages: [javascript, typescript]
    severity: ERROR
    mode: taint
    message: >-
      User-controlled input flows into a filesystem path — path traversal.
      A "../" sequence in the input escapes the intended directory.
    metadata:
      prism-severity: critical
      cwe: CWE-22
      owasp: "A01:2021 - Broken Access Control"
      fix: Resolve the path and verify it stays under the intended root (or use path.basename on the user segment).
    pattern-sources:
      - pattern: req.query
      - pattern: req.body
      - pattern: req.params
    pattern-sanitizers:
      - pattern: path.basename(...)
    pattern-sinks:
      - patterns:
          - pattern-either:
              - pattern: $FS.readFile($P, ...)
              - pattern: $FS.readFileSync($P, ...)
              - pattern: $FS.writeFile($P, ...)
              - pattern: $FS.writeFileSync($P, ...)
              - pattern: $FS.createReadStream($P, ...)
              - pattern: $FS.unlink($P, ...)
              - pattern: $FS.unlinkSync($P, ...)
          - focus-metavariable: $P

  - id: prism-command-injection-exec
    languages: [javascript, typescript]
    severity: ERROR
    mode: taint
    message: >-
      User-controlled input flows into a shell command — command injection.
    metadata:
      prism-severity: critical
      cwe: CWE-78
      owasp: "A03:2021 - Injection"
      fix: Use execFile/spawn with an argv array (no shell) and validate the arguments; never interpolate input into a command string.
    pattern-sources:
      - pattern: req.query
      - pattern: req.body
      - pattern: req.params
    pattern-sinks:
      - patterns:
          - pattern-either:
              - pattern: exec($CMD, ...)
              - pattern: execSync($CMD, ...)
              - pattern: $CP.exec($CMD, ...)
              - pattern: $CP.execSync($CMD, ...)
          - focus-metavariable: $CMD

  - id: prism-code-injection-eval
    languages: [javascript, typescript]
    severity: ERROR
    mode: taint
    message: >-
      User-controlled input reaches eval/new Function — remote code execution.
    metadata:
      prism-severity: critical
      cwe: CWE-95
      owasp: "A03:2021 - Injection"
      fix: Never evaluate user input as code. Parse it as data (JSON.parse) or dispatch through an explicit allowlist.
    pattern-sources:
      - pattern: req.query
      - pattern: req.body
      - pattern: req.params
    pattern-sinks:
      - patterns:
          - pattern-either:
              - pattern: eval($CODE)
              - pattern: new Function($CODE)
              - pattern: vm.runInNewContext($CODE, ...)
          - focus-metavariable: $CODE

  # ---------- Python ----------
  - id: prism-sqli-tainted-execute-py
    languages: [python]
    severity: ERROR
    mode: taint
    message: >-
      User-controlled input flows into a SQL statement passed to execute() —
      SQL injection.
    metadata:
      prism-severity: critical
      cwe: CWE-89
      owasp: "A03:2021 - Injection"
      fix: Use parameterized queries — cursor.execute("... WHERE id = %s", (value,)).
    pattern-sources:
      - pattern: flask.request.args
      - pattern: flask.request.form
      - pattern: flask.request.values
      - pattern: flask.request.json
      - pattern: request.args
      - pattern: request.form
      - pattern: request.values
      - pattern: request.json
      - pattern: request.GET
      - pattern: request.POST
    pattern-sinks:
      - patterns:
          - pattern-either:
              - pattern: $CUR.execute($Q, ...)
              - pattern: $CUR.executemany($Q, ...)
          - focus-metavariable: $Q

  - id: prism-command-injection-py
    languages: [python]
    severity: ERROR
    mode: taint
    message: >-
      User-controlled input flows into a shell command — command injection.
    metadata:
      prism-severity: critical
      cwe: CWE-78
      owasp: "A03:2021 - Injection"
      fix: Use subprocess with a list argv and shell=False; never format input into a command string.
    pattern-sources:
      - pattern: request.args
      - pattern: request.form
      - pattern: request.values
      - pattern: request.GET
      - pattern: request.POST
    pattern-sinks:
      - patterns:
          - pattern-either:
              - pattern: os.system($CMD)
              - pattern: os.popen($CMD)
              - pattern: subprocess.call($CMD, ..., shell=True, ...)
              - pattern: subprocess.run($CMD, ..., shell=True, ...)
              - pattern: subprocess.Popen($CMD, ..., shell=True, ...)
              - pattern: subprocess.check_output($CMD, ..., shell=True, ...)
          - focus-metavariable: $CMD

  - id: prism-ssrf-tainted-url-py
    languages: [python]
    severity: ERROR
    mode: taint
    message: >-
      User-controlled input is used as a request URL — server-side request
      forgery (SSRF).
    metadata:
      prism-severity: high
      cwe: CWE-918
      owasp: "A10:2021 - Server-Side Request Forgery"
      fix: Validate against an allowlist of hosts/schemes before requesting.
    pattern-sources:
      - pattern: request.args
      - pattern: request.form
      - pattern: request.values
      - pattern: request.GET
      - pattern: request.POST
    pattern-sinks:
      - patterns:
          - pattern-either:
              - pattern: requests.get($URL, ...)
              - pattern: requests.post($URL, ...)
              - pattern: requests.request($M, $URL, ...)
              - pattern: urllib.request.urlopen($URL, ...)
          - focus-metavariable: $URL

  - id: prism-path-traversal-open-py
    languages: [python]
    severity: ERROR
    mode: taint
    message: >-
      User-controlled input flows into open() — path traversal.
    metadata:
      prism-severity: critical
      cwe: CWE-22
      owasp: "A01:2021 - Broken Access Control"
      fix: Resolve the path and verify it stays under the intended root (os.path.realpath + startswith check).
    pattern-sources:
      - pattern: request.args
      - pattern: request.form
      - pattern: request.values
      - pattern: request.GET
      - pattern: request.POST
    pattern-sanitizers:
      - pattern: os.path.basename(...)
      - pattern: werkzeug.utils.secure_filename(...)
      - pattern: secure_filename(...)
    pattern-sinks:
      - patterns:
          - pattern: open($P, ...)
          - focus-metavariable: $P

  - id: prism-pickle-load-untrusted-py
    languages: [python]
    severity: ERROR
    mode: taint
    message: >-
      User-controlled data reaches pickle/marshal deserialization — arbitrary
      code execution on load.
    metadata:
      prism-severity: critical
      cwe: CWE-502
      owasp: "A08:2021 - Software and Data Integrity Failures"
      fix: Never unpickle untrusted data. Use JSON (or another data-only format) for anything that crosses a trust boundary.
    pattern-sources:
      - pattern: request.args
      - pattern: request.form
      - pattern: request.values
      - pattern: request.data
      - pattern: request.GET
      - pattern: request.POST
      - pattern: request.body
    pattern-sinks:
      - patterns:
          - pattern-either:
              - pattern: pickle.loads($D)
              - pattern: pickle.load($D)
              - pattern: marshal.loads($D)
              - pattern: shelve.open($D)
          - focus-metavariable: $D

  - id: prism-yaml-unsafe-load-py
    languages: [python]
    severity: WARNING
    message: >-
      yaml.load without SafeLoader deserializes arbitrary Python objects —
      code execution if the YAML is attacker-influenced.
    metadata:
      prism-severity: high
      cwe: CWE-502
      owasp: "A08:2021 - Software and Data Integrity Failures"
      fix: Use yaml.safe_load(), or pass Loader=yaml.SafeLoader.
    patterns:
      - pattern: yaml.load(...)
      - pattern-not: yaml.load(..., Loader=yaml.SafeLoader)
      - pattern-not: yaml.load(..., Loader=yaml.CSafeLoader)
`;
