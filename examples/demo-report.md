# RouteHawk Report

Target: `http://localhost:8088`
Scope: `localhost`

## Executive Summary

- Assets discovered: 1
- JavaScript files analyzed: 1
- Metadata records: 7
- Normalized endpoints: 9
- Manual test candidates: 8
- High-risk routes: 4
- Medium-risk routes: 0
- Warnings: 0

## Source Coverage

- graphql: 1
- javascript: 7
- openapi: 3
- robots: 2
- sitemap: 1

## Top Manual Test Candidates

### [High] POST /api/admin/users/{id}/role

Evidence:
- Admin-related path
- Contains object identifier pattern
- Corroborated by 2 source URLs
- Endpoint found in javascript
- Endpoint found in openapi
- Risk signal: +10 route discovered in frontend JavaScript
- Risk signal: +25 admin/authorization keyword present
- Risk signal: +25 sensitive business or user resource keyword
- Risk signal: +30 object identifier pattern in normalized route
- Roles or permissions related path
- User/account/customer object keyword

Manual test:
- Confirm the route is inside the authorized program scope.
- Request the endpoint as a low-privileged authenticated user.
- Compare behavior with an admin or authorized role when available.
- Check whether role and permission enforcement happens server-side.
- Review response codes, redirects, and partial data disclosure.

### [High] GET /api/users/{id}/billing

Evidence:
- Billing or payment related path
- Contains object identifier pattern
- Corroborated by 3 source URLs
- Endpoint found in javascript
- Endpoint found in openapi
- Endpoint found in sitemap
- Risk signal: +10 route discovered in frontend JavaScript
- Risk signal: +15 method GET often exposes object-level authz checks
- Risk signal: +25 sensitive business or user resource keyword
- Risk signal: +30 object identifier pattern in normalized route
- User/account/customer object keyword

Manual test:
- Login as User A.
- Capture a valid request for the endpoint.
- Replace the object identifier with another user's known identifier.
- Check status code, response body, and ownership enforcement.
- Repeat with read and write methods when authorized by the program rules.

### [High] GET /api/users/{id}/profile

Evidence:
- Contains object identifier pattern
- Endpoint found in javascript
- Risk signal: +10 route discovered in frontend JavaScript
- Risk signal: +15 method GET often exposes object-level authz checks
- Risk signal: +25 sensitive business or user resource keyword
- Risk signal: +30 object identifier pattern in normalized route
- User/account/customer object keyword

Manual test:
- Login as User A.
- Capture a valid request for the endpoint.
- Replace the object identifier with another user's known identifier.
- Check status code, response body, and ownership enforcement.
- Repeat with read and write methods when authorized by the program rules.

### [High] GET /api/orders/{id}

Evidence:
- Business object keyword
- Contains object identifier pattern
- Endpoint found in javascript
- Risk signal: +10 route discovered in frontend JavaScript
- Risk signal: +15 method GET often exposes object-level authz checks
- Risk signal: +25 sensitive business or user resource keyword
- Risk signal: +30 object identifier pattern in normalized route

Manual test:
- Login as User A.
- Capture a valid request for the endpoint.
- Replace the object identifier with another user's known identifier.
- Check status code, response body, and ownership enforcement.
- Repeat with read and write methods when authorized by the program rules.

### [Low] GET /internal/metrics

Evidence:
- Corroborated by 2 source URLs
- Debug/metrics/config route keyword
- Endpoint found in javascript
- Endpoint found in openapi
- Internal/private route keyword
- Risk signal: +10 route discovered in frontend JavaScript
- Risk signal: +15 method GET often exposes object-level authz checks
- Risk signal: +20 internal/debug keyword present

Manual test:
- Confirm the route is intentionally exposed to the tested environment.
- Request the endpoint without credentials and with a low-privileged session.
- Check for environment names, secrets, tokens, stack traces, or internal hostnames.
- Verify whether the endpoint leaks operational metrics or configuration values.
- Document only evidence and avoid changing server state.

### [Low] GET /graphql

Evidence:
- Corroborated by 2 source URLs
- Endpoint found in graphql
- Endpoint found in javascript
- GraphQL route keyword
- Risk signal: +10 route discovered in frontend JavaScript
- Risk signal: +15 method GET often exposes object-level authz checks
- Risk signal: +20 GraphQL endpoint behavior candidate

Manual test:
- Confirm the endpoint accepts GraphQL-shaped requests without aggressive probing.
- Check whether unauthenticated requests reveal schema or resolver error details.
- Compare authorization behavior across low-privileged and authorized sessions.
- Review object identifier arguments for ownership enforcement candidates.
- Avoid repeated introspection or heavy queries unless explicitly allowed.

### [Low] GET /debug/config

Evidence:
- Debug/metrics/config route keyword
- Endpoint found in javascript
- Risk signal: +10 route discovered in frontend JavaScript
- Risk signal: +15 method GET often exposes object-level authz checks
- Risk signal: +20 internal/debug keyword present

Manual test:
- Confirm the route is intentionally exposed to the tested environment.
- Request the endpoint without credentials and with a low-privileged session.
- Check for environment names, secrets, tokens, stack traces, or internal hostnames.
- Verify whether the endpoint leaks operational metrics or configuration values.
- Document only evidence and avoid changing server state.

### [Low] GET /admin

Evidence:
- Admin-related path
- Endpoint found in robots
- Risk signal: +15 method GET often exposes object-level authz checks
- Risk signal: +25 admin/authorization keyword present

Manual test:
- Confirm the route is inside the authorized program scope.
- Request the endpoint as a low-privileged authenticated user.
- Compare behavior with an admin or authorized role when available.
- Check whether role and permission enforcement happens server-side.
- Review response codes, redirects, and partial data disclosure.

## Route Groups

- `/api/admin` - 1 routes - max risk 95 - methods POST - tags admin, authorization, object-reference, user-object
- `/api/users` - 2 routes - max risk 85 - methods GET - tags billing, object-reference, user-object
- `/api/orders` - 1 routes - max risk 80 - methods GET - tags business-object, object-reference
- `/internal/metrics` - 1 routes - max risk 50 - methods GET - tags debug, internal
- `/graphql` - 1 routes - max risk 45 - methods GET - tags graphql
- `/debug/config` - 1 routes - max risk 45 - methods GET - tags debug
- `/admin` - 1 routes - max risk 40 - methods GET - tags admin
- `/api/public` - 1 routes - max risk 15 - methods GET - tags none
## Discovered Assets

- http://localhost - 200 - RouteHawk Demo Target - unknown

## JavaScript Files

- `http://localhost:8088/static/main.js` - 263 bytes - 7 endpoints - sha256 `019c3863ddd9...`

## Metadata

- security_headers: `http://localhost:8088` - status 200 - {'missing': ['content-security-policy', 'x-frame-options', 'x-content-type-options', 'referrer-policy']}
- cors: `http://localhost:8088` - status 200 - {'signals': []}
- robots: `http://localhost:8088/robots.txt` - status 200 - {'entries': 2}
- sitemap: `http://localhost:8088/sitemap.xml` - status 200 - {'urls': 1}
- openapi: `http://localhost:8088/swagger.json` - status 200 - {'paths': 3}
- security.txt: `http://localhost:8088/.well-known/security.txt` - status 200 - {'fields': ['contact', 'policy', 'preferred-languages'], 'contact_count': 1}
- graphql: `http://localhost:8088/graphql` - status 200 - {'get_status': 404, 'post_status': 200, 'graphql_response_hint': False}

## Endpoint Inventory

### POST `/api/admin/users/{id}/role`

- Risk score: 95
- Endpoint confidence: high
- Sources: javascript, openapi
- Tags: admin, authorization, object-reference, user-object
- Source URLs: 2
- Risk reasons: +10 route discovered in frontend JavaScript, +25 admin/authorization keyword present, +25 sensitive business or user resource keyword, +30 object identifier pattern in normalized route

### GET `/api/users/{id}/billing`

- Risk score: 85
- Endpoint confidence: high
- Sources: javascript, openapi, sitemap
- Tags: billing, object-reference, user-object
- Source URLs: 3
- Risk reasons: +10 route discovered in frontend JavaScript, +15 method GET often exposes object-level authz checks, +25 sensitive business or user resource keyword, +30 object identifier pattern in normalized route

### GET `/api/users/{id}/profile`

- Risk score: 80
- Endpoint confidence: low
- Sources: javascript
- Tags: object-reference, user-object
- Source URLs: 1
- Risk reasons: +30 object identifier pattern in normalized route, +25 sensitive business or user resource keyword, +15 method GET often exposes object-level authz checks, +10 route discovered in frontend JavaScript

### GET `/api/orders/{id}`

- Risk score: 80
- Endpoint confidence: low
- Sources: javascript
- Tags: business-object, object-reference
- Source URLs: 1
- Risk reasons: +30 object identifier pattern in normalized route, +25 sensitive business or user resource keyword, +15 method GET often exposes object-level authz checks, +10 route discovered in frontend JavaScript

### GET `/internal/metrics`

- Risk score: 50
- Endpoint confidence: high
- Sources: javascript, openapi
- Tags: debug, internal
- Source URLs: 2
- Risk reasons: +10 route discovered in frontend JavaScript, +15 method GET often exposes object-level authz checks, +20 internal/debug keyword present

### GET `/graphql`

- Risk score: 45
- Endpoint confidence: medium
- Sources: graphql, javascript
- Tags: graphql
- Source URLs: 2
- Risk reasons: +10 route discovered in frontend JavaScript, +15 method GET often exposes object-level authz checks, +20 GraphQL endpoint behavior candidate

### GET `/debug/config`

- Risk score: 45
- Endpoint confidence: low
- Sources: javascript
- Tags: debug
- Source URLs: 1
- Risk reasons: +15 method GET often exposes object-level authz checks, +10 route discovered in frontend JavaScript, +20 internal/debug keyword present

### GET `/admin`

- Risk score: 40
- Endpoint confidence: low
- Sources: robots
- Tags: admin
- Source URLs: 1
- Risk reasons: +15 method GET often exposes object-level authz checks, +25 admin/authorization keyword present

### GET `/api/public`

- Risk score: 15
- Endpoint confidence: low
- Sources: robots
- Tags: none
- Source URLs: 1
- Risk reasons: +15 method GET often exposes object-level authz checks

## Warnings

_No warnings._
