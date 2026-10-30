# Web, API and WASM adapter

Find the actual hosting root and server/client boundary. A Next.js deployment includes server artifacts that must not be copied into a public static directory. Stage only deliberately public output. Upload private maps to restricted error tooling, exclude them from hosting/caches, and check the deployed origin/CDN. A `hidden` map is public if its file is served.

Use supported minification/tree shaking. WASM is inspectable bytecode, not encryption. A WASM migration needs toolchain, ABI and performance testing. CloneGuard v0.1 does not compile JavaScript to WASM or implement a virtual machine.

Review JS, HTML, JSON, service-worker precaches, manifests, backups and archives. Keys prefixed `NEXT_PUBLIC_`/`VITE_` are public. Keep credentials and authorization decisions server-side. Avoid DOM randomization that breaks hydration, accessibility, tests, analytics or customer automation.

## API controls

Retain TLS and standard serialization. A client that decrypts traffic can inspect it. Use authenticated sessions, object/action/tenant authorization on every request, minimal response fields, scoped short-lived entitlements, revocation and aggregate quotas.

Bind integrity assertions/capabilities to audience, user/tenant, method, normalized route, body digest, expiry and a server-validated challenge as appropriate. Use standard cryptographic libraries and documented canonical encoding. Replay prevention needs shared transactional nonce/counter storage across workers. A process-local set or HMAC in client JavaScript is not an enterprise gate.

Rate limits need shared state, trusted proxy configuration, account/tenant dimensions, bounded cardinality, 429/Retry-After handling, monitoring and an emergency override. Start behavioral detection in observation mode and measure false positives. WebDriver is not an authorization decision. Do not silently corrupt customer data when automation is suspected.

Keep semantic HTML. Hidden HTML/ARIA prompt injection is not reliable access control and can harm legitimate assistive agents. Honeypot routes may record abuse indicators without creating real credentials or exposing private data.

## Validate

Test signed-out, cross-tenant, expired, replayed and malformed requests plus valid retry/clock-skew behavior. Check keyboard/screen reader flow, supported automation, CSP, hydration and service-worker upgrades. Compare public file inventories and perform hosted map URL checks when deployment access is authorized. Local scanning does not establish CDN privacy.

Source: [OWASP authorization guidance](https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html).
