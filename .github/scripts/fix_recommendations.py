"""
Fix recommendation databases for the PR Review Agent comment builder.
Imported by post_comment.py.

Kept in a separate .py file so the workflow YAML never contains backtick
code fences (which break YAML block-scalar / heredoc parsing).
"""

# ── Snyk SAST fix DB ──────────────────────────────────────────────────────────
SNYK_SAST_FIX = {
    "hardcodedpassword": (
        "Remove the hardcoded credential. Read it from environment variables or a secrets manager.",
        "\n".join([
            "```java",
            "// \u274c Before",
            'private static final String PASSWORD = "admin123";',
            "",
            "// \u2705 After \u2014 read from environment / secrets manager",
            'private static final String PASSWORD = System.getenv("APP_PASSWORD");',
            "```",
        ]),
    ),
    "hardcredsecret": (
        "Remove the hardcoded credential. Read it from environment variables or a secrets manager.",
        "\n".join([
            "```java",
            "// \u2705 After",
            'private static final String SECRET = System.getenv("APP_SECRET");',
            "```",
        ]),
    ),
    "sqli": (
        "Use PreparedStatement with parameter binding \u2014 never concatenate user input into SQL.",
        "\n".join([
            "```java",
            "// \u274c Before",
            "String query = \"SELECT * FROM users WHERE username='\" + username + \"'\";",
            "stmt.executeQuery(query);",
            "",
            "// \u2705 After",
            "PreparedStatement ps = connection.prepareStatement(",
            '    "SELECT * FROM users WHERE username = ?");',
            "ps.setString(1, username);",
            "ResultSet rs = ps.executeQuery();",
            "```",
        ]),
    ),
    "sqlinjection": (
        "Use PreparedStatement with parameter binding \u2014 never concatenate user input into SQL.",
        "\n".join([
            "```java",
            "// \u274c Before",
            "String query = \"SELECT * FROM users WHERE username='\" + username + \"'\";",
            "",
            "// \u2705 After",
            "PreparedStatement ps = connection.prepareStatement(",
            '    "SELECT * FROM users WHERE username = ?");',
            "ps.setString(1, username);",
            "```",
        ]),
    ),
    "weakrandom": (
        "Replace java.util.Random with java.security.SecureRandom for security-sensitive values.",
        "\n".join([
            "```java",
            "// \u274c Before",
            "Random random = new Random();",
            "int otp = 100000 + random.nextInt(900000);",
            "",
            "// \u2705 After",
            "SecureRandom secureRandom = new SecureRandom();",
            "int otp = 100000 + secureRandom.nextInt(900000);",
            "```",
        ]),
    ),
    "insecurerandom": (
        "Replace java.util.Random with java.security.SecureRandom for security-sensitive values.",
        "\n".join([
            "```java",
            "// \u2705 After",
            "import java.security.SecureRandom;",
            "SecureRandom sr = new SecureRandom();",
            "```",
        ]),
    ),
    "nullpointer": (
        "Add a null-check or use Objects.requireNonNull() before dereferencing the parameter.",
        "\n".join([
            "```java",
            "// \u274c Before",
            "public int getLength(String value) {",
            "    return value.length(); // NPE if value is null",
            "}",
            "",
            "// \u2705 After",
            "public int getLength(String value) {",
            "    if (value == null) return 0;",
            "    return value.length();",
            "}",
            "```",
        ]),
    ),
    "xss": (
        "Encode all user-controlled output before writing to HTML. Use OWASP Java Encoder.",
        "\n".join([
            "```java",
            "// \u2705 After \u2014 using OWASP Java Encoder",
            "import org.owasp.encoder.Encode;",
            "String safe = Encode.forHtml(userInput);",
            "```",
        ]),
    ),
    "pathtraversal": (
        "Canonicalize and validate file paths to prevent directory traversal attacks.",
        "\n".join([
            "```java",
            "// \u2705 After",
            'Path base   = Paths.get("/allowed/base").toRealPath();',
            "Path target = base.resolve(userInput).normalize();",
            "if (!target.startsWith(base)) {",
            '    throw new SecurityException("Path traversal attempt blocked");',
            "}",
            "```",
        ]),
    ),
    "deserializ": (
        "Avoid Java native deserialization of untrusted data. Use JSON/Protobuf or an object filter.",
        "\n".join([
            "```java",
            "// \u2705 After \u2014 use ObjectInputFilter (Java 9+)",
            "ObjectInputStream ois = new ObjectInputStream(inputStream);",
            "ois.setObjectInputFilter(ObjectInputFilter.Config.createFilter(",
            '    "com.example.SafeClass;!*"));',
            "```",
        ]),
    ),
}

SNYK_SAST_GENERIC = (
    "Review the flagged code and apply the principle of least privilege / input validation.",
    "> Refer to the [Snyk vulnerability database](https://security.snyk.io) for rule-specific remediation.",
)

# ── Snyk dependency CVE fix DB ────────────────────────────────────────────────
SNYK_DEP_FIX = {
    "jackson-databind": (
        "Upgrade `jackson-databind` to **2.15.4** or later.",
        "\n".join([
            "```xml",
            "<!-- \u2705 pom.xml -->",
            "<dependency>",
            "  <groupId>com.fasterxml.jackson.core</groupId>",
            "  <artifactId>jackson-databind</artifactId>",
            "  <version>2.15.4</version>",
            "</dependency>",
            "```",
        ]),
    ),
    "commons-collections": (
        "Upgrade `commons-collections4` to **4.4** or later.",
        "\n".join([
            "```xml",
            "<!-- \u2705 pom.xml -->",
            "<dependency>",
            "  <groupId>org.apache.commons</groupId>",
            "  <artifactId>commons-collections4</artifactId>",
            "  <version>4.4</version>",
            "</dependency>",
            "```",
        ]),
    ),
    "spring-web": (
        "Upgrade `spring-web` to **5.3.39** or later.",
        "\n".join([
            "```xml",
            "<!-- \u2705 pom.xml -->",
            "<dependency>",
            "  <groupId>org.springframework</groupId>",
            "  <artifactId>spring-web</artifactId>",
            "  <version>5.3.39</version>",
            "</dependency>",
            "```",
        ]),
    ),
    "spring-webmvc": (
        "Upgrade `spring-webmvc` to **5.3.39** or later.",
        "\n".join([
            "```xml",
            "<!-- \u2705 pom.xml -->",
            "<dependency>",
            "  <groupId>org.springframework</groupId>",
            "  <artifactId>spring-webmvc</artifactId>",
            "  <version>5.3.39</version>",
            "</dependency>",
            "```",
        ]),
    ),
}

SNYK_DEP_GENERIC = (
    "Upgrade the dependency to the latest stable version that resolves the CVE.",
    "> Check [Snyk Advisor](https://snyk.io/advisor) or [MVN Repository](https://mvnrepository.com).",
)

# ── Dispatcher rule fix DB ────────────────────────────────────────────────────
DISP_FIX = {
    "DISP-001": (
        'Remove the `/glob "*" /type "allow"` catch-all and replace with explicit allow rules.',
        "\n".join([
            "```apache",
            "# \u274c Before",
            '/0001 { /glob "*" /type "allow" }',
            "",
            "# \u2705 After \u2014 deny first, then allow only what is needed",
            '/0001 { /glob "*"          /type "deny"  }',
            '/0002 { /glob "/content/*" /type "allow" }',
            '/0003 { /glob "/etc/designs/*" /type "allow" }',
            '/0004 { /glob "/clientlibs/*"  /type "allow" }',
            "```",
        ]),
    ),
    "DISP-002": (
        'Make the very first `/type` rule a `/type "deny"` to enforce an allow-list.',
        "\n".join([
            "```apache",
            "# \u2705 Add as rule /0001 (before any allow rules)",
            '/0001 { /type "deny" /url "*" }',
            "```",
        ]),
    ),
    "DISP-003": (
        'Remove any rule that allows `/crx/*` or `/system/*`. These paths must never be exposed.',
        "\n".join([
            "```apache",
            "# \u274c Remove these rules entirely",
            '# /0010 { /glob "/crx/*"    /type "allow" }',
            '# /0011 { /glob "/system/*" /type "allow" }',
            "",
            "# \u2705 Explicitly deny them",
            '/0010 { /glob "/crx/*"    /type "deny" }',
            '/0011 { /glob "/system/*" /type "deny" }',
            "```",
        ]),
    ),
    "DISP-004": (
        'Add a specific deny rule for `/bin/` after the broad allow, or remove the allow entirely.',
        "\n".join([
            "```apache",
            '/0020 { /glob "/bin/public/*" /type "allow" }',
            '/0021 { /glob "/bin/*"        /type "deny"  }',
            "```",
        ]),
    ),
    "DISP-005": (
        'Add explicit deny overrides for sensitive paths before the allow-all cache rule.',
        "\n".join([
            "```apache",
            "/rules {",
            '  /0001 { /glob "/crx/*"    /type "deny" }',
            '  /0002 { /glob "/system/*" /type "deny" }',
            '  /0003 { /glob "/bin/*"    /type "deny" }',
            '  /0004 { /glob "/libs/*"   /type "deny" }',
            '  /0005 { /glob "/conf/*"   /type "deny" }',
            '  /0006 { /glob "*"         /type "allow" }',
            "}",
            "```",
        ]),
    ),
    "DISP-005b": (
        "List query parameters to ignore so they do not fragment the cache.",
        "\n".join([
            "```apache",
            "/ignoreUrlParams {",
            '  /0001 { /glob "utm_*"  /type "allow" }',
            '  /0002 { /glob "gclid"  /type "allow" }',
            '  /0003 { /glob "fbclid" /type "allow" }',
            '  /0004 { /glob "_ga"    /type "allow" }',
            '  /0005 { /glob "*"      /type "deny"  }',
            "}",
            "```",
        ]),
    ),
    "DISP-006": (
        "Add a `Content-Security-Policy` response header to the VHost file.",
        "\n".join([
            "```apache",
            "# \u2705 Add inside <VirtualHost> block",
            "Header always set Content-Security-Policy",
            "  \"default-src 'self'; img-src 'self' data:; frame-ancestors 'none';\"",
            "```",
        ]),
    ),
    "DISP-007": (
        "Add an `X-Frame-Options` response header to prevent clickjacking.",
        "\n".join([
            "```apache",
            "# \u2705 Add inside <VirtualHost> block",
            'Header always set X-Frame-Options "SAMEORIGIN"',
            "```",
        ]),
    ),
    "DISP-008": (
        'Set `/allowAuthorized "0"` to prevent caching of authenticated responses.',
        "\n".join([
            "```apache",
            "# \u274c Before",
            '/allowAuthorized "1"',
            "",
            "# \u2705 After",
            '/allowAuthorized "0"',
            "```",
        ]),
    ),
    "DISP-009": (
        "Remove the rule that caches this sensitive AEM path.",
        "\n".join([
            "```apache",
            "# \u2705 Replace allow with deny",
            '/0004 { /glob "/crx/*"    /type "deny" }',
            '/0005 { /glob "/system/*" /type "deny" }',
            "```",
        ]),
    ),
    "DISP-010": (
        "Remove `/libs/*` and `/conf/*` from cache allow rules \u2014 these are AEM internal paths.",
        "\n".join([
            "```apache",
            "# \u2705 Add explicit deny",
            '/0006 { /glob "/libs/*" /type "deny" }',
            '/0007 { /glob "/conf/*" /type "deny" }',
            "```",
        ]),
    ),
    "DISP-GQL": (
        "Restrict the GraphQL endpoint to persisted queries only.",
        "\n".join([
            "```apache",
            '<LocationMatch "/_cq_graphql">',
            "  <LimitExcept GET>",
            "    Require all denied",
            "  </LimitExcept>",
            "</LocationMatch>",
            "```",
        ]),
    ),
}

DISP_FIX_GENERIC = (
    "Review the dispatcher configuration and apply the principle of least privilege.",
    "> Consult the [AEM Dispatcher Security Checklist](https://experienceleague.adobe.com/docs/experience-manager-dispatcher/using/getting-started/security-checklist.html).",
)


def snyk_sast_fix(rule_id):
    rid = (rule_id or "").lower()
    for key, val in SNYK_SAST_FIX.items():
        if key in rid:
            return val
    return SNYK_SAST_GENERIC


def snyk_dep_fix(location):
    loc = (location or "").lower()
    for key, val in SNYK_DEP_FIX.items():
        if key in loc:
            return val
    return SNYK_DEP_GENERIC


def disp_fix(rule):
    return DISP_FIX.get(rule, DISP_FIX_GENERIC)
