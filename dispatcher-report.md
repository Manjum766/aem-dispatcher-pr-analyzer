## AEM Dispatcher Security Analysis — CRITICAL (score: 100/100)

| Severity | Count |
|---|---|
| 🔴 Critical | 3 |
| 🟠 High     | 4 |
| 🟡 Medium   | 1 |
| 🔵 Low      | 0 |

### 🟠 `DISP-008` · Authenticated content may be cached
> **Severity:** HIGH  
> **File:** `dispatcher/src/conf.dispatcher/cache.any` — line 6  
> `/allowAuthorized "1"` instructs the dispatcher to cache responses for authenticated requests. This risks serving one user's private content to another.

### 🔴 `DISP-005` · Cache allow-all with no deny overrides
> **Severity:** CRITICAL  
> **File:** `dispatcher/src/conf.dispatcher/cache.any` — line 11  
> The cache rules contain `/glob "*" /type "allow"` as the only rule — every URL including admin paths will be cached. Add explicit deny overrides for `/crx/*`, `/system/*`, `/bin/*`, `/libs/*`, and `/conf/*`.

### 🟠 `DISP-009` · /bin/* cached — Sling servlet endpoints cached
> **Severity:** HIGH  
> **File:** `dispatcher/src/conf.dispatcher/cache.any` — line 13  
> Line 13: `/bin/*` — Caching `/bin/*` exposes all Sling servlet endpoints. Add a specific deny rule or remove this allow rule.

### 🔴 `DISP-009` · /crx/* cached — AEM repository browser exposed
> **Severity:** CRITICAL  
> **File:** `dispatcher/src/conf.dispatcher/cache.any` — line 14  
> Line 14: `/crx/*` — Caching `/crx/*` allows unauthenticated access to the CRX repository browser and package manager. Remove this rule entirely.

### 🔴 `DISP-009` · /system/* cached — AEM system console exposed
> **Severity:** CRITICAL  
> **File:** `dispatcher/src/conf.dispatcher/cache.any` — line 15  
> Line 15: `/system/*` — Caching `/system/*` exposes the Felix OSGi console and health-check endpoints. Remove this rule entirely.

### 🟠 `DISP-010` · /libs/* cached — AEM internal path exposed
> **Severity:** HIGH  
> **File:** `dispatcher/src/conf.dispatcher/cache.any` — line 16  
> Line 16: `/libs/*` is cached. `/libs/*` and `/conf/*` contain AEM framework files and OSGi configurations that should not be publicly cached.

### 🟠 `DISP-010` · /conf/* cached — AEM internal path exposed
> **Severity:** HIGH  
> **File:** `dispatcher/src/conf.dispatcher/cache.any` — line 17  
> Line 17: `/conf/*` is cached. `/libs/*` and `/conf/*` contain AEM framework files and OSGi configurations that should not be publicly cached.

### 🟡 `DISP-005b` · All query parameters used as cache keys
> **Severity:** MEDIUM  
> **File:** `dispatcher/src/conf.dispatcher/cache.any` — line 20  
> The `ignoreUrlParams` block contains `/glob "*" /type "allow"`, meaning every query parameter is included in the cache key. UTM/tracking params will fragment the cache and reduce hit rate. Explicitly ignore known tracking params.

---
**Overall Risk Score:** 100/100 (CRITICAL)  
Fix all CRITICAL and HIGH issues before merging.