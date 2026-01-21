# Security Review for GitLab MCP Server

**Review Date:** 2026-01-21
**Version Reviewed:** 2.0.13 (with upstream master merged)
**Reviewer:** Claude (AI Security Analysis)

## Executive Summary

This security review was conducted on the GitLab MCP (Model Context Protocol) server codebase. The review covered authentication, authorization, input validation, network security, session management, and other security-critical areas. Overall, the codebase demonstrates **good security practices** with several strong security controls in place. However, some areas require attention and improvements.

**Overall Security Rating: MODERATE-HIGH** ✅

---

## Table of Contents

1. [Security Strengths](#security-strengths)
2. [Security Findings](#security-findings)
3. [Detailed Analysis](#detailed-analysis)
4. [Recommendations](#recommendations)
5. [Compliance & Best Practices](#compliance--best-practices)

---

## Security Strengths

The codebase implements several robust security controls:

### 1. Authentication & Authorization ✅

**Strengths:**
- **Multiple Authentication Methods**: Supports Personal Access Tokens (PAT), OAuth2, cookie-based auth, and remote authorization
- **OAuth2 with PKCE**: Implements proper OAuth2 flow with PKCE (Proof Key for Code Exchange) for enhanced security (oauth.ts:127-141)
- **Token Validation**: Validates token format and minimum length (index.ts:6947-6952)
  ```typescript
  const validateToken = (token: string): boolean => {
    if (token.length < 20) return false;
    if (!/^[-a-zA-Z0-9_.]+$/.test(token)) return false;
    return true;
  };
  ```
- **Secure Token Storage**: OAuth tokens stored with file permissions `0o600` (owner-only access) (oauth.ts:251)
- **Token Refresh Mechanism**: Automatic token refresh with 5-minute buffer before expiry (oauth.ts:280-288)
- **Session-based Auth Context**: Uses AsyncLocalStorage for secure session isolation (index.ts:600)
- **Remote Authorization**: Per-session token management with proper isolation

### 2. Session Management ✅

**Strengths:**
- **Session Timeout**: Configurable session timeout (1-86400 seconds, default 3600s) (index.ts:314-328)
- **Session Isolation**: Each session maintains its own auth context via AsyncLocalStorage
- **Automatic Cleanup**: Sessions are cleaned up on timeout or explicit closure (index.ts:7032-7041, 7282-7299)
- **Session Limits**: Configurable maximum concurrent sessions (default 1000, max 10000) (index.ts:331-336)
- **Graceful Shutdown**: Proper cleanup of all sessions on server shutdown (index.ts:7282-7311)

### 3. Rate Limiting & DoS Protection ✅

**Strengths:**
- **Per-Session Rate Limiting**: 60 requests/minute per session (configurable 1-1000) (index.ts:6928, 6957-6972)
- **Capacity Limits**: Maximum concurrent sessions to prevent resource exhaustion (index.ts:7084-7091)
- **ReDoS Protection**: Uses `\S+` instead of `.+` in regex patterns to prevent Regular Expression Denial of Service (index.ts:7004-7007)
- **Rate Limit Tracking**: Comprehensive metrics for rejected requests (index.ts:6930-6939)

### 4. Input Validation ✅

**Strengths:**
- **Zod Schema Validation**: All API inputs validated with Zod schemas (schemas.ts)
- **Type Coercion with Validation**: Safe type coercion for numeric IDs (schemas.ts:14, etc.)
- **URL Validation**: Uses native `new URL()` for URL parsing and validation (index.ts:362-366)
- **Project ID Whitelisting**: `GITLAB_ALLOWED_PROJECT_IDS` restricts access to specific projects (index.ts:1398-1476)
- **Regex Pattern Validation**: Invalid regex patterns are caught and logged, not executed (index.ts:5411-5419)

### 5. Network Security ✅

**Strengths:**
- **TLS/SSL Configuration**: Proper HTTPS agent configuration with custom CA cert support (index.ts:422-448)
- **Proxy Support**: HTTP/HTTPS/SOCKS proxy support with SSL options (gitlab-client-pool.ts:61-82)
- **URL Normalization**: Consistent API URL handling prevents endpoint confusion (index.ts:1378-1390)
- **Connection Pooling**: Efficient connection reuse with pool size limits (gitlab-client-pool.ts:98-101)
- **Agent Reuse**: HTTP agents properly reused for performance and security

### 6. API Security ✅

**Strengths:**
- **Read-Only Mode**: Optional read-only mode restricts write operations (index.ts:1278-1369)
- **Tool Filtering**: Regex-based tool denial for granular access control (index.ts:399-401)
- **encodeURIComponent**: Proper URL encoding prevents injection in API paths (index.ts:1493, 1530, etc.)
- **Error Handling**: Structured error handling without sensitive data leakage (index.ts:1435-1447)

### 7. Cryptography & Secrets ✅

**Strengths:**
- **PKCE for OAuth**: Uses SHA-256 challenge method for OAuth2 (oauth.ts:127-141)
- **Secure Random**: Uses `randomUUID()` for session IDs (index.ts:7139)
- **Token Expiry**: Proper token expiration handling with refresh (oauth.ts:280-288)

---

## Security Findings

### HIGH PRIORITY 🔴

#### H-1: Insecure SSL/TLS Configuration Option

**Severity:** HIGH
**Location:** `index.ts:422-423`, `gitlab-client-pool.ts:47-48`

**Issue:**
The server allows disabling SSL certificate validation via `NODE_TLS_REJECT_UNAUTHORIZED=0`:

```typescript
if (NODE_TLS_REJECT_UNAUTHORIZED === "0") {
  sslOptions = { rejectUnauthorized: false };
}
```

**Risk:**
- Man-in-the-Middle (MitM) attacks
- Interception of GitLab API tokens and sensitive data
- Data tampering and credential theft

**Recommendation:**
1. Add prominent security warnings in README when this option is documented
2. Log a CRITICAL warning when this option is enabled
3. Consider removing this option for production deployments
4. Require custom CA certificates instead for self-signed scenarios

```typescript
if (NODE_TLS_REJECT_UNAUTHORIZED === "0") {
  logger.fatal("⚠️  CRITICAL SECURITY WARNING: SSL certificate verification is DISABLED!");
  logger.fatal("⚠️  This makes your connection vulnerable to Man-in-the-Middle attacks!");
  logger.fatal("⚠️  NEVER use this in production. Use GITLAB_CA_CERT_PATH instead.");
  sslOptions = { rejectUnauthorized: false };
}
```

---

#### H-2: Potential Server-Side Request Forgery (SSRF) in Dynamic API URL

**Severity:** HIGH
**Location:** `index.ts:6986-6993`

**Issue:**
When `ENABLE_DYNAMIC_API_URL=true`, the server accepts arbitrary GitLab API URLs from client headers without proper validation beyond URL format:

```typescript
const dynamicApiUrl = (req.headers["x-gitlab-api-url"] as string | undefined)?.trim();
if (ENABLE_DYNAMIC_API_URL && dynamicApiUrl) {
  try {
    new URL(dynamicApiUrl); // Only validates URL format
    apiUrl = normalizeGitLabApiUrl(dynamicApiUrl);
  } catch {
    return null;
  }
}
```

**Risk:**
- SSRF attacks targeting internal services
- Access to cloud metadata endpoints (AWS: 169.254.169.254, GCP: metadata.google.internal)
- Port scanning internal networks
- Bypassing firewall restrictions

**Recommendation:**

1. **Implement URL Allowlist**: Only accept URLs from a pre-configured allowlist
2. **Block Private IP Ranges**: Reject RFC1918 private IPs, localhost, link-local, etc.
3. **Block Cloud Metadata Endpoints**: Explicitly block AWS, GCP, Azure metadata services
4. **Protocol Restriction**: Only allow HTTPS (not HTTP, file://, ftp://, etc.)

```typescript
const BLOCKED_HOSTS = [
  'localhost', '127.0.0.1', '0.0.0.0',
  '169.254.169.254', // AWS metadata
  'metadata.google.internal', // GCP metadata
  '169.254.169.254',
];

const isPrivateIP = (hostname: string): boolean => {
  // Check for private IP ranges: 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16
  const ipRegex = /^(\d{1,3}\.){3}\d{1,3}$/;
  if (!ipRegex.test(hostname)) return false;

  const parts = hostname.split('.').map(Number);
  return (
    parts[0] === 10 ||
    (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) ||
    (parts[0] === 192 && parts[1] === 168)
  );
};

const validateApiUrl = (apiUrl: string): boolean => {
  const url = new URL(apiUrl);

  // Only HTTPS allowed
  if (url.protocol !== 'https:') return false;

  // Check blocklist
  if (BLOCKED_HOSTS.some(h => url.hostname.includes(h))) return false;

  // Block private IPs
  if (isPrivateIP(url.hostname)) return false;

  return true;
};
```

---

### MEDIUM PRIORITY 🟡

#### M-1: Insufficient Token Validation

**Severity:** MEDIUM
**Location:** `index.ts:6947-6952`

**Issue:**
Token validation only checks length (≥20) and character set. GitLab Personal Access Tokens have specific formats that aren't fully validated.

```typescript
const validateToken = (token: string): boolean => {
  if (token.length < 20) return false;
  if (!/^[-a-zA-Z0-9_.]+$/.test(token)) return false;
  return true;
};
```

**Risk:**
- Accepts malformed tokens that will fail later
- No distinction between different token types
- Potential for token confusion attacks

**Recommendation:**
Add format-specific validation for GitLab tokens:

```typescript
const validateToken = (token: string): boolean => {
  // GitLab PAT: glpat-xxxxxxxxxxxxxxxxxxxx (20+ chars)
  // GitLab Pipeline token: glptt-xxxxxxxxxxxxxxxxxxxx
  // GitLab Runner token: glrt-xxxxxxxxxxxxxxxxxxxx
  if (token.startsWith('glpat-')) {
    return token.length >= 26 && /^glpat-[a-zA-Z0-9_-]+$/.test(token);
  }
  // Legacy tokens (backwards compatibility)
  if (token.length >= 20 && /^[-a-zA-Z0-9_.]+$/.test(token)) {
    return true;
  }
  return false;
};
```

---

#### M-2: Cookie File Security

**Severity:** MEDIUM
**Location:** `index.ts:463-515`

**Issue:**
- Cookie files are read but not validated for permissions
- No check if cookie file is world-readable
- Cookie jar loaded synchronously on first request

**Risk:**
- Cookies could be stolen if file permissions are insecure
- Sensitive session data exposure

**Recommendation:**

```typescript
const createCookieJar = async (): Promise<CookieJar | null> => {
  if (!resolvedCookiePath) return null;

  // Check file permissions
  try {
    const stats = await fs.promises.stat(resolvedCookiePath);
    const mode = stats.mode & parseInt('777', 8);
    if (mode & parseInt('077', 8)) {
      logger.error({
        path: resolvedCookiePath,
        mode: mode.toString(8)
      }, 'Cookie file has insecure permissions. Should be 600 (owner read/write only)');
      throw new Error('Insecure cookie file permissions');
    }
  } catch (error) {
    logger.error({ error, path: resolvedCookiePath }, "Cookie file security check failed");
    return null;
  }

  // ... rest of cookie loading logic
};
```

---

#### M-3: Metrics Endpoint Information Disclosure

**Severity:** MEDIUM
**Location:** `index.ts:7218-7232`

**Issue:**
The `/metrics` endpoint exposes detailed operational information without authentication:

```typescript
app.get("/metrics", (_req: Request, res: Response) => {
  res.json({
    ...metrics,
    activeSessions: Object.keys(streamableTransports).length,
    authenticatedSessions: Object.keys(authBySession).length,
    uptime: process.uptime(),
    memoryUsage: process.memoryUsage(),
    // ... more internal details
  });
});
```

**Risk:**
- Enumeration of active sessions
- Resource usage profiling for DoS attacks
- Information gathering for targeted attacks

**Recommendation:**
1. Require authentication for `/metrics` endpoint
2. Implement IP allowlisting for metrics access
3. Rate-limit the metrics endpoint
4. Consider Prometheus-compatible format with configurable exposure levels

---

#### M-4: Session Timeout Not Configurable Per-Session

**Severity:** MEDIUM
**Location:** `index.ts:409, 7027-7042`

**Issue:**
Session timeout is global, not configurable per session or user role. All sessions expire after the same duration.

**Risk:**
- High-privilege sessions have same timeout as low-privilege
- Cannot enforce shorter timeouts for sensitive operations

**Recommendation:**
Implement role-based or operation-based timeout configuration.

---

### LOW PRIORITY 🟢

#### L-1: GraphQL Query Injection

**Severity:** LOW
**Location:** `schemas.ts` (GraphQL execution)

**Issue:**
The server executes arbitrary GraphQL queries provided by users. While this is by design, there's no query complexity analysis or depth limiting.

**Risk:**
- Expensive queries causing DoS
- Data exfiltration through deeply nested queries

**Recommendation:**
1. Implement query complexity analysis
2. Set maximum query depth
3. Query timeout limits
4. Consider query allowlisting for production

---

#### L-2: Logging of Sensitive Data

**Severity:** LOW
**Location:** Various logging statements

**Issue:**
Some log statements may include tokens or sensitive data in error messages.

**Recommendation:**
- Audit all log statements
- Implement log sanitization
- Never log full tokens (only last 4 characters for debugging)

---

#### L-3: No Security Headers in HTTP Responses

**Severity:** LOW
**Location:** Express app configuration

**Issue:**
Missing security headers like:
- `X-Content-Type-Options: nosniff`
- `X-Frame-Options: DENY`
- `Strict-Transport-Security`
- `Content-Security-Policy`

**Recommendation:**
Use `helmet` package for automatic security headers:

```typescript
import helmet from 'helmet';
app.use(helmet({
  strictTransportSecurity: { maxAge: 31536000 },
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'none'"],
      scriptSrc: ["'none'"],
    },
  },
}));
```

---

## Detailed Analysis

### Authentication Flow Analysis

1. **OAuth Flow** (oauth.ts):
   - ✅ Implements PKCE correctly
   - ✅ State parameter for CSRF protection
   - ✅ Token refresh with expiry buffer
   - ⚠️  Shared OAuth server on same port could have race conditions

2. **Remote Authorization** (index.ts:7094-7124):
   - ✅ Per-session token storage
   - ✅ AsyncLocalStorage for context isolation
   - ✅ Automatic cleanup on timeout
   - ⚠️  No token revocation mechanism

3. **Cookie-Based Auth** (index.ts:470-515):
   - ✅ Supports Netscape cookie format
   - ✅ Cookie jar isolation
   - ⚠️  No validation of cookie file permissions

### Input Validation Analysis

All user inputs are validated through Zod schemas. Key validations:

- ✅ Project IDs: String coercion with encoding
- ✅ File paths: URI encoded
- ✅ Regex patterns: Error handling for invalid patterns
- ✅ URLs: Native URL parser validation
- ⚠️  GraphQL queries: No complexity limits

### Network Security Analysis

- ✅ HTTPS enforced via agent configuration
- ✅ Proxy support (HTTP/HTTPS/SOCKS)
- ✅ Custom CA certificates
- 🔴 Optional SSL verification bypass (security risk)
- 🔴 Dynamic API URLs without SSRF protection

### Session Management Analysis

- ✅ UUID-based session IDs (crypto-random)
- ✅ Session isolation via AsyncLocalStorage
- ✅ Configurable timeout (1-86400s)
- ✅ Automatic cleanup
- ✅ Graceful shutdown
- 🟡 Global timeout (not per-session)
- 🟡 No session fingerprinting

---

## Recommendations

### Critical (Immediate Action Required)

1. **Fix SSRF Vulnerability** (H-2)
   - Implement URL allowlisting for dynamic API URLs
   - Block private IP ranges and cloud metadata endpoints
   - Add comprehensive URL validation

2. **Strengthen SSL/TLS Security** (H-1)
   - Add critical warnings for `NODE_TLS_REJECT_UNAUTHORIZED=0`
   - Consider deprecating this option
   - Enforce CA certificate usage for self-signed scenarios

### High Priority (Within 1 Sprint)

3. **Enhance Token Validation** (M-1)
   - Implement GitLab-specific token format validation
   - Add token type detection

4. **Secure Metrics Endpoint** (M-3)
   - Add authentication to `/metrics`
   - Implement IP allowlisting

5. **Cookie File Security** (M-2)
   - Validate file permissions on load
   - Reject world-readable cookie files

### Medium Priority (Within 2 Sprints)

6. **Implement Security Headers** (L-3)
   - Add helmet middleware
   - Configure appropriate CSP

7. **GraphQL Security** (L-1)
   - Add query complexity analysis
   - Implement depth limiting

8. **Audit Logging** (L-2)
   - Implement log sanitization
   - Never log full tokens

### Long-term Improvements

9. **Security Monitoring**
   - Add intrusion detection
   - Implement anomaly detection for unusual API usage

10. **Regular Security Testing**
    - Automated vulnerability scanning
    - Periodic penetration testing
    - Dependency vulnerability audits

---

## Compliance & Best Practices

### OWASP Top 10 Coverage

| Risk | Status | Notes |
|------|--------|-------|
| A01: Broken Access Control | ✅ Mitigated | Project ID whitelisting, session isolation |
| A02: Cryptographic Failures | 🟡 Partial | PKCE, but SSL bypass option exists |
| A03: Injection | ✅ Mitigated | Zod validation, URL encoding |
| A04: Insecure Design | ✅ Good | Well-structured auth flows |
| A05: Security Misconfiguration | 🔴 Risk | SSL bypass, unprotected metrics |
| A06: Vulnerable Components | ✅ Good | Recent dependencies |
| A07: Authentication Failures | ✅ Mitigated | Multiple auth methods, session management |
| A08: Software/Data Integrity | ✅ Good | Signed packages (npm) |
| A09: Logging Failures | 🟡 Partial | Good logging, but may include sensitive data |
| A10: SSRF | 🔴 Risk | Dynamic API URLs without validation |

### Security Best Practices Compliance

✅ **Followed:**
- Input validation with schema libraries
- Parameterized API calls (no SQL injection risk)
- HTTPS enforcement
- Session management
- Rate limiting
- Token expiration
- Secure random for session IDs

⚠️ **Needs Improvement:**
- SSRF protection
- SSL/TLS hardening
- Metrics endpoint protection
- Security headers

---

## Conclusion

The GitLab MCP server demonstrates **strong foundational security** with robust authentication, session management, and input validation. The main security concerns are:

1. **SSRF vulnerability** in dynamic API URL feature (HIGH)
2. **SSL bypass option** creates MitM risk (HIGH)
3. **Unprotected metrics endpoint** (MEDIUM)

With the recommended fixes, particularly addressing the SSRF and SSL concerns, this codebase would achieve a **HIGH security rating**.

### Next Steps

1. Prioritize fixes for H-1 and H-2 (SSRF and SSL)
2. Implement security headers and metrics authentication
3. Enhance token validation
4. Regular security audits and dependency updates
5. Consider third-party security assessment

---

**Review Completed:** 2026-01-21
**Next Review Recommended:** 2026-04-21 (3 months)
