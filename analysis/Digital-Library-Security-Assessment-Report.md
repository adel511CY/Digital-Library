# Software Vulnerability Assessment and Defense: Security Analysis and Mitigation of the Digital Library Application

**Course:** CECY481 – Software Security
**Institution:** University of Jeddah, College of Computer Science & Engineering
**Project type:** Course project (Software Vulnerability Assessment and Defense)

| Group Members | Student ID | Contribution |
|---|---|---|
| عادل عوض المقاطي (Adel Almquti) | 2440382 | [Insert specific contribution] |
| [Insert Name] | [Insert ID] | [Insert specific contribution] |
| [Insert Name] | [Insert ID] | [Insert specific contribution] |

**Instructor:** [Insert Name]
**Submission Date:** [Insert Date]

---

## Abstract

This report documents a security assessment of the **Digital Library**, a Node.js/Express/SQLite web application that lets users browse, search for, and reserve books, with a separate administrator role for managing books and reservation records. The repository provides two parallel implementations: an intentionally **vulnerable** version (`The APPS/web vulnerability/`) and a **modified** version with security improvements (`The APPS/web/`). The assessment combined automated static analysis (Semgrep), manual source-code review, and dynamic testing against both implementations running locally.

Four vulnerabilities documented in the project's own materials were independently reproduced and retested: SQL injection enabling authentication bypass in the login form (**V1**), SQL injection via the book-search endpoint allowing UNION-based extraction of data from the `reservations` table (**V2**), DOM-based cross-site scripting through an unsafe `innerHTML` sink in the search results view (**V3**), and session/identity spoofing through a client-readable, unsigned cookie (**V4**). All four were confirmed fixed in the modified version by direct retesting: parameterized queries blocked the SQL injection payloads, and a signed, verified JWT cookie blocked the forged-identity attack.

The assessment also went beyond the four original findings, in part by enumerating every route actually defined in `server.js` rather than relying only on the routes named in the project's own documentation. Live testing showed that the modified version's reservation-update endpoint (`POST /update_reservations:id`) has **no authentication or authorization check at all**, letting any anonymous visitor change another user's reservation status and administrator notes, and that a second, separate endpoint (`GET /delete_reservations:id`) requires only a valid login but no ownership check, letting any registered user cancel any other user's reservation. A hypothesis that the administrator-authorization middleware (`IamAdmin`) contains a logic bug was tested directly against the real source code and **did not reproduce** — the actual condition is written correctly, and both a non-admin and an admin account were tested live to confirm the middleware behaves as intended. A new, previously undocumented stored-XSS-style vector was found and demonstrated in the modified application: the `image_url` field accepted by the admin-only "add book" endpoint is not escaped when interpolated into an `<img src="...">` attribute, so a crafted value can break out of the attribute and inject a live `onerror` handler that every visitor to the public book catalog would execute. The project's own JWT-signing secret (`JWTSSS`, stored in `The APPS/web/.env`) was found to be tracked in the project's Git history since the very first commit; whether the GitHub repository itself is public could not be confirmed from this environment, so that specific point is reported as a limitation rather than a confirmed exposure.

All testing in this assessment was performed locally, against a locally run copy of the application seeded with disposable test accounts and test data, using the project's own documented setup steps. No public or third-party system was targeted.

---

## 1. Introduction

Modern web applications routinely handle authentication, personal data, and privileged administrative functions, which makes them an attractive target for attackers and makes secure coding practice a core professional skill. This project applies the software-security analysis techniques taught in CECY481 to a concrete, representative application: the Digital Library, a small library-management system built with Node.js, Express, and SQLite.

The objective of this assessment is to (1) understand the application's architecture and attack surface, (2) apply at least two complementary security-analysis techniques, (3) investigate and validate at least three distinct suspected weaknesses with root-cause and impact analysis, and (4) recommend and, where possible, verify concrete defenses. The scope is limited to the source code supplied in the project's own repository (`The APPS/web vulnerability/` and `The APPS/web/`) and to **authorized, local** testing of that code — no part of this assessment involved scanning or attacking any third-party or publicly hosted system.

## 2. Application Overview

The Digital Library is a small library-management web application. A visitor can browse the book catalog and search by title without logging in. A **registered user** can create an account, log in, and reserve available books, and can view their own reservations. An **administrator** account can additionally add, update, and remove books, and review and update reservation records (status and administrator notes).

![Digital Library homepage](./photo/Figure%201.png)

*Figure 1. The Digital Library homepage, showing the public entry points (Register, Login, Browse Books) and the advertised feature set, including the "Safe & Secure" claim this assessment evaluates.*

![Login form and administrator "Manage Books" panel](./photo/Figure%202.png)

*Figure 2. Top: the login form and the public search bar on the Books page. Bottom: the administrator panel's "Manage Books" view, reachable only after authenticating with an administrator account.*

The backend is a single Express application (`server.js`) backed by a SQLite database (`web.db`) opened through `better-sqlite3`. The locked dependency versions, taken directly from each implementation's `package-lock.json` (not estimated from the version ranges in `package.json`), are:

| Component | Vulnerable version | Modified version |
|---|---|---|
| `express` | 5.1.0 | 5.1.0 |
| `better-sqlite3` | 12.4.6 | 12.4.6 |
| `bcrypt` | 6.0.0 | 6.0.0 |
| `jsonwebtoken` | 9.0.2 | 9.0.2 |
| `cookie-parser` | 1.4.7 | 1.4.7 |
| `sanitize-html` | 2.17.0 | 2.17.0 |
| `dotenv` | 17.2.3 | 17.2.3 |
| `ejs` | 3.1.10 | 3.1.10 |

Both implementations share the same three-table schema:

- **`users`** — `id`, `username`, `email`, `password_hash`, `full_name`, `is_admin`, `created_at`.
- **`books`** — `id`, `title`, `author`, `description`, `isbn`, `quantity`, `available_quantity`, `image_url`, `created_at`, `updated_at`.
- **`reservations`** — `id`, `user_id`, `book_id`, `status`, `reservation_date`, `updated_at`, `admin_notes`.

The application listens on `http://localhost:3000/`. A sample of the public book catalog, retrieved from the running application during this assessment via `GET /get_all_book`, is shown below to illustrate the data shape referenced throughout the rest of this report:

![Raw JSON response from GET /get_all_book](./photo/Figure%207.png)

*Figure 7. Unauthenticated `GET /get_all_book` response, showing the full book catalog (title, author, description, ISBN, quantity, `image_url`, timestamps). This is the same data shape later shown to be forgeable in Section 6.5.*

## 3. Application Architecture and Attack Surface

### 3.1 Entry points and sensitive operations

| Entry point | Method | Auth required (modified version) | Sensitivity |
|---|---|---|---|
| `/login`, `/register` | POST | None | Authentication — primary attack surface for V1 |
| `/search_book:query` | GET | None | Takes attacker-controlled input into a SQL query — V2 |
| `/get_all_book`, `/getbookbyID:id` | GET | None | Public data read |
| `/create_reservations` | POST | Login | Writes to `reservations` |
| `/getmyreservations` | GET | Login | Reads own reservations |
| `/update_reservations:id` | POST | **None** (confirmed — Section 6.5) | Writes `status` and `admin_notes` for **any** reservation |
| `/delete_reservations:id` | GET | Login only — **no ownership check** (confirmed — Section 6.6) | Sets `status='cancelled'` for **any** reservation ID, regardless of who owns it |
| `/create_book`, `/update_book:id`, `/update_value:id`, `/delete_book:id` | POST | Login + Admin | Writes to `books` — `image_url`/`title` are later rendered unescaped (Section 6.7) |
| `/admin` | GET | Login + Admin | Serves the admin panel |
| cookie `webisTheBest` | — | — | Carries the signed (modified) / unsigned (vulnerable) identity claim — V4 |

### 3.2 Trust boundaries

1. **Client ↔ Server** — every request body, query string, and cookie is attacker-controlled. The vulnerable version trusts the `username`/`password` body fields enough to splice them into SQL text (V1), trusts the search `query` the same way (V2), and trusts the `webisTheBest` cookie's contents outright (V4). The browser's own DOM is a second client-side trust boundary: the vulnerable `books.html` inserts the search query into the live page via `innerHTML` without encoding (V3).
2. **Authentication ↔ Authorization** — a valid session (the `logIN` middleware) is distinct from administrator privilege (the `IamAdmin` middleware). Section 6.5 shows that for `/update_reservations:id` this boundary is missing entirely — the route has neither check.
3. **Application ↔ Database** — all database access goes through `better-sqlite3`'s synchronous API. The vulnerable version builds some queries by string interpolation (V1, V2); the modified version uses parameterized `?` placeholders for the same queries (verified in Section 7).

### 3.3 Attack Surface Diagram

![Attack Surface Diagram of the Digital Library Application](./attack-surface-diagram.jpg)

*Figure 3. Attack surface diagram, covering the four zones (external actors, browser/client layer, application server, database layer) and the three trust boundaries described in Section 3.2, with the routes and findings A1–A5 annotated directly on the diagram: A1 (login SQLi, Section 6.1), A2 (search SQLi, Section 6.2), A3 (unverified cookie, Section 6.4), A4 (DOM XSS, Section 6.3), and A5 (missing access control on `POST /update_reservations:id`, Section 6.5). This diagram was produced separately from the 19 numbered screenshots in `analysis/photo/` and is saved directly in `analysis/`, alongside this report, per the project brief's own allowance for a separately generated diagram. One gap in the diagram as drawn: `GET /delete_reservations:id`, listed here under "Authenticated User Operations," has no ownership check at all — any logged-in user, not only the reservation's owner, can cancel any reservation by ID. This is a second, distinct missing-authorization finding, analyzed in full in Section 6.6, since the diagram itself does not flag it with its own "A" marker.*

## 4. Security Assessment Methodology

Two complementary, evidence-producing techniques were used, consistent with the course requirement of at least two techniques including one automated tool:

1. **Automated SAST — Semgrep.** The project's own evidence (Figures 4 and 20, discussed below) was produced with `semgrep scan --config p/javascript` / `semgrep --config-auto`, pulling rules from the Semgrep Registry (`semgrep.dev`). This assessment's own environment has no outbound network access to `semgrep.dev`, so an equivalent, independently reproducible scan was run instead using **Semgrep 1.186.0** against an offline clone of the official open-source rule repository, `github.com/semgrep/semgrep-rules`, pinned to commit `a5ad1714f00c9f7fde980cab0ea1d6dc6d414fd2` (2026-11-10), using the `javascript/` rule tree (177 rules after resolving the directory). This is a different rule set from the registry's curated `p/javascript` pack, so finding counts differ between the project's screenshots and this report's own scan — both are reported, clearly labeled by source, rather than merged.
2. **Manual source-code review.** Both `server.js` files (545 and 547 lines) and all `views/*.html` files were read in full and diffed line-by-line between the vulnerable and modified directories, rather than only the excerpts quoted in the project's own documentation. All line numbers cited in this report were taken from the exact files inside the supplied `Digital-Library-main.zip` archive.
3. **Dynamic testing.** Both applications were installed with `npm ci` (using each directory's own lockfile), seeded with disposable test accounts (`admin`/`alice`), and run locally (`node server.js`, `http://localhost:3000/`). All four original findings and the two additional findings below were re-tested against the **running** applications — not inferred from source code alone. Where the project's own screenshots already demonstrate a result, they are cited directly; where no screenshot covered a specific step, this assessment's own request/response evidence is quoted instead and clearly marked as such.

### 4.1 Methodology comparison

| Technique | Purpose | Evidence | Strengths | Limitations |
|---|---|---|---|---|
| Semgrep (SAST) | Static source-code analysis | Project screenshots (Figures 4, 20) + this assessment's own JSON scan output | Fast, repeatable, flags patterns across the whole codebase | Did not have a rule that matches `better-sqlite3`'s template-literal query style for the DOM-XSS sink in `books.html` (an `.html` file with inline `<script>`, outside Semgrep's default JS file matching) — a false negative discussed in Section 5 |
| Manual code review | Root-cause investigation | Exact file/line citations in this report | Context-aware; found the two additional issues in Sections 6.5 and 6.6 that neither Semgrep configuration flagged | Depends on reviewer time and expertise; does not by itself prove runtime exploitability |
| Dynamic testing (local) | Runtime validation | Live request/response captures quoted in Sections 6 and 7 | Demonstrates actual, observed behavior of the running application, including the before/after retest | Covers only the inputs and paths actually tested |

### 4.2 Semgrep results — as supplied by the project

![Project's own Semgrep scan of the vulnerable application](./photo/Figure%204.png)

*Figure 4. The project team's own Semgrep CLI run (registry `p/javascript` config, 309 JS rules) against the vulnerable `server.js`, reporting 5 blocking findings: an unsanitized `console.log(req.user)` (information exposure), two `session-fixation` findings on the `res.cookie("webisTheBest", ...)` call (lines 216 and 274 in that scan), and two `cookies-secure-missing-express` findings on the same call. This corroborates the V4 finding (Section 6.4): the cookie is set without integrity protection and, in the vulnerable version, without the `secure` flag.*

![Project's own Semgrep scan of the modified application](./photo/Figure%2020.png)

*Figure 20. The project team's own `semgrep --config-auto` run (Semgrep CLI 1.176.1) against the modified `web/` directory: 4 blocking findings on 16 files, including `express-check-csurf-middleware-usage` (no CSRF middleware detected) and a `django-no-csrf-token` finding on `login.html`'s `<form id="loginForm" action="/login" method="POST">`. The second finding is a **technology mismatch** — this rule is written for Django template forms, and this project uses neither Django nor server-rendered forms with a templating engine that would carry a CSRF token — but the underlying observation it points at (the login form has no anti-CSRF token and no CSRF middleware protects the route) is accurate and independently confirmed by this assessment's own scan below.*

### 4.3 Semgrep results — this assessment's own, independently reproducible scan

Running `semgrep scan --config <offline semgrep-rules clone>/javascript <target dir> --json` against each implementation produced:

**Vulnerable version** (`The APPS/web vulnerability/`, 15 files scanned, 177 rules):

| Rule | File : Lines | Severity | Finding |
|---|---|---|---|
| `express.security.injection.tainted-sql-string` | `server.js:193` | ERROR | User input manually concatenated into a SQL string — this is the **V1** login query |
| `express.security.injection.tainted-sql-string` | `server.js:349` | ERROR | User input manually concatenated into a SQL string — this is the **V2** search query |
| `express.security.audit.express-check-csurf-middleware-usage` | `server.js:11` | INFO | No CSRF middleware detected |
| `lang.correctness.missing-template-string-indicator` (×2) | `public/js/config.js:28–36` | INFO | Code-style observation, not security-relevant |

**Modified version** (`The APPS/web/`, 16 files scanned, 177 rules):

| Rule | File : Lines | Severity | Finding |
|---|---|---|---|
| `express.security.audit.express-check-csurf-middleware-usage` | `server.js:11` | INFO | No CSRF middleware detected (unchanged from the vulnerable version) |
| `lang.security.audit.detect-redos` | `server.js:237` | WARNING | The email-format regular expression `^[\w-\.]+@([\w-]+\.)+[\w-]{2,4}$` was flagged as a possible ReDoS pattern |
| `lang.correctness.missing-template-string-indicator` (×2) | `public/js/config.js:28–36` | INFO | Same code-style observation as above |

The two `tainted-sql-string` findings disappear entirely in the modified-version scan — a result consistent with, and corroborating, the manual-review and dynamic-retest conclusion in Section 7 that both SQL injection points were fixed with parameterized queries.

The `detect-redos` warning was investigated rather than taken at face value, per the course's "an unverified tool alert is not automatically a vulnerability" guidance. The flagged regular expression was tested directly in Node.js with adversarial inputs designed to trigger catastrophic backtracking in patterns of this shape (long repeated-group strings ending in a character that forces the engine to exhaust every partition before failing), up to 40 repetitions of the ambiguous group:

```js
const re = /^[\w-\.]+@([\w-]+\.)+[\w-]{2,4}$/;
re.test("user@" + "a.".repeat(40) + "!");   // ~0.0 ms — no blow-up observed
```

No measurable slowdown was observed up to this input size in Node's V8 engine, because the mandatory literal `.` inside the repeated group constrains the ambiguity that classic ReDoS patterns rely on. This finding is reported as **suspected but not confirmed** (a likely false positive for this specific engine and pattern shape), rather than omitted or silently accepted — consistent with the rubric's requirement to distinguish confirmed vulnerabilities from unconfirmed tool alerts.

The absence of a Semgrep alert for the DOM-based XSS sink in `books.html` (V3, Section 6.3) and for the missing-authorization issue on `/update_reservations:id` (Section 6.5) does **not** mean those issues are secure — both were confirmed independently by manual review and live dynamic testing. This illustrates, concretely, the course's point that an automated scan's silence is not proof of security.

## 5. Security Analysis Results Summary

Three or more distinct suspected weaknesses were investigated with root-cause analysis, in addition to the four vulnerabilities already documented by the project team. The following seven are carried through to full analysis below:

1. **V1 — SQL injection in `/login` → authentication bypass** (confirmed, reproduced live).
2. **V2 — SQL injection in `/search_book` → unauthorized data extraction from `reservations`** (confirmed, reproduced live).
3. **V3 — DOM-based XSS via `innerHTML` in the search results view** (confirmed — execution proven both by the project's own screenshot and by this assessment's own DOM-level reproduction).
4. **V4 — Unsigned, client-forgeable session cookie → privilege escalation** (confirmed, reproduced live).
5. **Missing authorization on `/update_reservations:id`** (confirmed, reproduced live — **present in both versions**, not fixed by the security pass).
6. **Missing object-level authorization (IDOR) on `/delete_reservations:id`** (new finding from this assessment, confirmed by direct reproduction with two unrelated test accounts — **present in both versions**).
7. **Attribute-breakout stored XSS via the `image_url` book field** (new finding from this assessment, confirmed by direct reproduction — present in the modified version).

One suspected weakness carried over from the project's own assumptions was investigated and **not confirmed**: the hypothesis that the `IamAdmin` middleware's conditional logic is broken (the assignment brief's own Section 8.1 discussion, addressed in full in Section 6.8 below). This is reported explicitly as a tested-and-rejected hypothesis rather than silently dropped, per the requirement to distinguish confirmed findings from false positives.

## 6. Vulnerability Analysis

### 6.1 V1 — Login SQL Injection and Authentication Bypass

**CWE-89** (Improper Neutralization of Special Elements used in an SQL Command), with a resulting **CWE-287** (Improper Authentication) impact.

**Affected file (vulnerable):** `The APPS/web vulnerability/server.js`, line 193.

```js
const TheRseultFROMsql = db.prepare(
  `SELECT * FROM users WHERE username = '${req.body.username}' AND password_hash = '${req.body.password}' `
).get()
```

**Root cause.** Both the `username` and `password` fields from the request body are spliced directly into the SQL text with no parameterization and no escaping. Note also (line 205, commented out) that bcrypt comparison is disabled — the vulnerable version compares the raw submitted password against whatever ended up in `password_hash`, which is itself stored in plaintext (see the related, separate finding below).

**Attacker-controlled input:** the `username` and `password` POST body fields.

**Exploitation and practical demonstration.** This assessment ran the application locally and submitted the password field `x' OR 1=1 -- ` with username `admin`:

```
POST /login  {"username":"admin","password":"x' OR 1=1 -- "}
→ HTTP/1.1 200 OK
  Set-Cookie: webisTheBest=j%3A%7B%22exp%22%3A...%2C%22userid%22%3A1%2C%22username%22%3A%22admin%22%7D
  {"success":true,"message":"Registration successful"}
```

The resulting query becomes `... AND password_hash = 'x' OR 1=1 -- '`, which is always true, so `.get()` returns the first row regardless of the real password — here, the administrator account (`userid: 1`). The same result was obtained with the classic form-encoded payload `username=admin&password='OR 1=1 --`. This confirms the project's own documented claim that this input reaches the administrator account, by direct reproduction rather than by trusting the original write-up.

**Separate finding — plaintext password storage.** Independently of the SQL injection, `The APPS/web vulnerability/server.js` lines 257–261 store the password exactly as submitted:

```js
// const salt = bcrypt.genSaltSync(10)
// req.body.password = bcrypt.hashSync(req.body.password , salt)
const insertData = db.prepare("INSERT INTO users (username , email , password_hash , full_name ) VALUES ( ? , ? , ? , ? )")
```

This is tracked separately as **CWE-256** (Plaintext Storage of a Password): even without the SQL injection, a leaked `web.db` file or a successful read-only SQL injection elsewhere would expose every user's real password, not a hash.

**Threat scenario.** Any unauthenticated visitor who can reach the login form can authenticate as any existing account, including the administrator, without knowing any password. Severity: **Critical** — no privileges required, trivially repeatable, full authentication bypass with administrative impact.

#### Modified implementation

**File:** `The APPS/web/server.js`, lines 191 and 199.

```js
const sqlStatmentToGetINFO = db.prepare("SELECT * FROM users WHERE username = ?")
const TheRseultFROMsql = sqlStatmentToGetINFO.get(req.body.username)
...
const isSamePassword = bcrypt.compareSync(req.body.password , TheRseultFROMsql.password_hash)
```

![Modified login route source code in VS Code](./photo/Figure%2010.png)

*Figure 10. The modified `/login` route open in the editor (lines 171–197), showing the parameterized `SELECT ... WHERE username = ?` lookup followed by `bcrypt.compareSync` — the manual source-code review evidence for this sub-finding.*

Registration (line 264) now hashes the password with `bcrypt.hashSync`. These are two independent defenses for two independent problems: the `?` placeholder removes the SQL-injection channel entirely (the username can no longer change the query's structure), while `bcrypt.compareSync` means even a leaked `password_hash` cannot be used directly to log in. Fixing one without the other would have left a real gap, so it is worth stating plainly that both changes were necessary and both were found present.

**Verification (retest).** The identical payload was replayed against the running modified application:

```
POST /login  {"username":"admin","password":"x' OR 1=1 -- "}
→ HTTP/1.1 400 Bad Request   {"errors":["invalid password OR username "]}
```

and the real password behaves normally:

```
POST /login  {"username":"admin","password":"admin"}
→ HTTP/1.1 200 OK
  Set-Cookie: webisTheBest=eyJhbGciOiJIUzI1NiIs...   (a three-part JWT, not a bare JSON object)
```

Status: **Fix Implemented and Verified** (retested live in this assessment; see also the project's own retest screenshots, Section 7).

![Baseline login-rejection test (duplicate pair)](./photo/Figure%203.png)
![Baseline login-rejection test (duplicate pair)](./photo/Figure%205.png)

*Figures 3 and 5. Two captures of the same baseline/control test — a syntactically valid but incorrect username/password pair (`adel` / `testA@@123`) correctly rejected with HTTP 400. These establish what normal, non-malicious rejection looks like, for contrast with the bypass above. The two images are near-duplicates of the same test (different crop/scale, identical request and response content) and are not given separate captions; per Section 10.6, this is noted rather than invented into two distinct pieces of evidence. Neither this pair nor any of the other 19 supplied screenshots happens to capture the successful V1 bypass response itself, so the quoted request/response above is this assessment's own first-hand reproduction.*

### 6.2 V2 — SQL Injection in Book Search

**CWE-89.**

**Affected file (vulnerable):** `The APPS/web vulnerability/server.js`, line 349.

```js
const sqlstatment_return_info_of_book = db.prepare(
  `SELECT * FROM books WHERE title LIKE '%${req.params.query}%'`
).all()
```

![Vulnerable search route and the start of the admin-protected update_book route](./photo/Figure%206.png)

*Figure 6. The vulnerable `/search_book/:query` handler (lines 344–363 in this capture) and the start of `/update_book:id`. Note that `/update_book:id` here is already gated behind `logIN, IamAdmin` even in the vulnerable version — only `/update_reservations:id` (Section 6.5) is left completely unprotected in both versions.*

**Root cause and exploitation.** The `query` route parameter is interpolated directly into the `LIKE` clause. A UNION-based payload changes the column count and source table of the result set:

```
A' AND 1=0 UNION SELECT NULL AS A, NULL AS c, NULL AS f, * FROM reservations --
```

This assessment submitted that exact payload to the running vulnerable application:

```
GET /search_book/A'%20AND%201%3D0%20UNION%20SELECT%20NULL...FROM%20reservations%20--
→ HTTP/1.1 200 OK
  {"success":true,"data":[{"id":null,"title":null,"author":null,
    "description":1,"isbn":2,"quantity":1,"available_quantity":"pending",
    "image_url":"2026-11-20 21:06:14","created_at":"2026-11-20 21:06:14",
    "updated_at":"secret admin note about alice"}], "query": "..."}
```

Because the `books` table has 10 columns and the UNION supplies `NULL, NULL, NULL` plus the 7 columns of `reservations`, the response's JSON keys are mislabeled (an artifact of the column-count match, not of the data itself), but the values are unambiguous: `user_id=1`, `book_id=2`, `status="pending"`, and — in the last field — the reservation's `admin_notes` text, here a test value planted for this assessment (`"secret admin note about alice"`). **No authentication of any kind was used for this request.** This confirms the project's own claim that unauthorized reservation data can be extracted, with concrete, reproduced evidence of exactly which field leaks.

**Threat scenario and impact.** Any unauthenticated visitor can read arbitrary columns from any table the query planner can reach via UNION — here demonstrated against `reservations`, including the confidential `admin_notes` field. Confidentiality impact: **High**. Severity: **Critical** — no authentication required, and the technique generalizes to other tables (e.g., `users`) with a different column/type-matched payload.

#### Modified implementation

**File:** `The APPS/web/server.js`, line 353.

```js
const sqlstatment_return_info_of_book = db.prepare("SELECT * FROM books WHERE title LIKE ?")
const result_theinfo_of_book = sqlstatment_return_info_of_book.all(`%${req.params.query}%`)
```

![Modified search route source code in VS Code](./photo/Figure%2011.png)

*Figure 11. The modified `/search_book:query` handler (lines 340–357), showing the parameterized query and the `sanitizeHTML` call on the query string, with the start of the admin-gated `/update_book:id` route visible below it for contrast with Section 6.5.*

The modified version also runs the query through `sanitizeHTML(req.params.query.trim(), {allowedTags: [], allowedAttributes: {}})` before use (line 350 in `server.js`). This is worth being precise about: **the parameterized query, not the HTML sanitization, is what stops the SQL injection.** `sanitize-html` strips HTML tags; it has no effect on SQL metacharacters such as `'`, and would not have stopped this attack on its own. The `?` placeholder is what prevents the string from ever being parsed as part of the SQL statement.

**Route-pattern note.** The vulnerable version's route is `/search_book/:query` (with a slash); the modified version's is `/search_book:query` (no slash). This was checked against the corresponding frontend code rather than assumed to be either a mistake or an intentional improvement: `views/books.html` calls `fetch(`/search_book/${query}`)` in the vulnerable version and `fetch(`/search_book${query}`)` in the modified version — the frontend was updated to match. This is an unconventional (non-RESTful) path style but it is internally consistent and was confirmed working end-to-end in the live retest below; it is not itself a security control.

**Verification (retest).** The identical UNION payload was replayed against the running modified application:

```
GET /search_book%27 AND 1=0 UNION SELECT NULL AS A, NULL AS c, NULL AS f, * FROM reservations --
→ HTTP/1.1 200 OK   {"success":true,"data":[]}
```

An empty result — the payload is now treated as a literal (and non-matching) search string. This exact behavior was also independently captured by the project team:

![Project's retest: rejected login payload, immediately followed by the empty-result UNION retest](./photo/Figure%2014.png)
![Project's retest: UNION payload returns an empty result set](./photo/Figure%2015.png)

*Figures 14 and 15. These two captures were initially ambiguous as to which implementation they were taken against, since the rejection message text ("invalid password OR username") is identical in both versions' source code. They were resolved by tracing the actual SQL that the classic payload `password='OR 1=1 --` would produce against the **vulnerable** query (it does satisfy `OR 1=1` and should return 200, not 400) — so an HTTP 400 here is only consistent with the **modified**, parameterized version. Figure 15's empty `"data":[]` for the same UNION payload used above independently matches this assessment's own retest. Both are therefore classified as Phase-4 **retest/verification evidence**, not original-vulnerability evidence, and are cross-referenced again in Section 7.*

Status: **Fix Implemented and Verified.**

### 6.3 V3 — Cross-Site Scripting (reclassified: DOM-based, not Reflected)

**CWE-79** (Improper Neutralization of Input During Web Page Generation).

**Affected file (vulnerable):** `The APPS/web vulnerability/views/books.html`, lines 124–131.

```js
function zz(query){
    document.getElementById("yourSerch").innerHTML = `
        <div class="card" id="yourSerch">
            <h2>Available Books</h2>
            ${!query ? "" : `<h4>your search is ${query}</h4>`}
        </div>
    `;
}
```

**Re-classification, verified rather than assumed.** The project's own documentation calls this "Reflected XSS." Tracing the actual data flow: the search query travels from the search box → a `fetch()` call → the JSON response's own `query` field → the client-side `zz()` function → directly into `element.innerHTML` in the browser. The server never re-renders the page with the payload embedded in server-generated HTML (which is what "reflected XSS" technically describes); the injection happens entirely inside the browser's own DOM, driven by client-side JavaScript. This is **DOM-based XSS**, and this report uses that term rather than silently repeating the original classification.

**Proof of the injection step (this assessment's own reproduction).** The exact `zz()` function and the documented payload (`p' --"><img src="x" onerror="alert('Adel almquti')">`) were run in a headless DOM (jsdom) to confirm precisely what the browser parser does with the string, independent of any screenshot:

```js
// exact payload parsed as real HTML, not inert text:
h4.childNodes = [ TEXT("your search is p' --\">"), ELEMENT<IMG> ]
img.getAttribute('onerror') === "alert('Adel almquti')"
img instanceof HTMLImageElement === true
```

This shows unambiguously that the payload is not merely echoed as text — the HTML parser creates a genuine, live `<img>` element with a working `onerror` handler as a direct child of the page. jsdom does not implement image network loading, so it cannot itself fire the `onerror` event (a tool limitation, stated plainly rather than glossed over); a real browser attempts to load `src="x"`, fails, and fires `onerror` immediately.

**Proof of execution (project's own screenshot, in a real browser).** This last step — actual `onerror` firing — is exactly what the project's own evidence shows, using a simpler proof-of-concept payload than the documented one:

![Browser alert dialog triggered by the injected search payload](./photo/Figure%208.png)

*Figure 8. A native Chrome `alert()` dialog ("1") is shown on top of the Books page, with the vulnerable `zz()`-rendered output partially visible behind it. This is genuine execution evidence from a real browser, which complements the jsdom parse-level proof above (jsdom cannot fire `onerror` itself, so this image supplies the step the headless reproduction could not).*

![The documented payload entered into the search field](./photo/Figure%2016.png)

*Figure 16. The documented payload as typed into the search box and reflected back into the page's `query` display. This image shows the payload in place but, unlike Figure 8, does not itself show an alert firing — it is evidence of the input reaching the field, not of execution, and is captioned accordingly rather than over-stated.*

**Impact and severity.** In a real deployment this allows arbitrary JavaScript execution in the victim's browser session — cookie theft (subject to `httpOnly`, discussed in Section 6.4), page defacement, or action-on-behalf-of-victim attacks. Severity: **High**.

#### Modified implementation

`The APPS/web/views/books.html` removes the `zz()` search-echo function entirely, but still uses `innerHTML` to render book data in two places (lines 160 and 200 of that file): the book list grid and the book-details panel. Both interpolate `book.image_url`, `book.title`, `book.author`, and `book.description` — all values that ultimately come from the database — directly into template strings without HTML-encoding. The server-side `ValidationBook` function (lines 295–310 of `server.js`) runs these same fields through `sanitizeHTML(..., {allowedTags: [], allowedAttributes: {}})` before they are stored, which strips actual HTML tags. This is not a complete defense, as Section 6.7 demonstrates concretely: a value that contains no HTML tag at all (for example, a quote character that breaks out of an attribute) passes straight through `sanitize-html` unchanged. That specific, confirmed gap is analyzed in full in Section 6.7 rather than left as a generic residual-risk statement.

Recommended defenses for all remaining `innerHTML` sinks: build DOM nodes with `document.createElement` / `textContent` instead of string concatenation, or, if template strings must be used, HTML-encode every interpolated value and additionally validate/encode `image_url` specifically as a URL before placing it in a `src` attribute.

### 6.4 V4 — Cookie Manipulation and Session Integrity

**CWE-565** (Reliance on Cookies without Validation and Integrity Checking), with a resulting **CWE-287** impact.

**Affected file (vulnerable):** `The APPS/web vulnerability/server.js`, line 97.

```js
const decoded = /* jwt.verify( */ req.cookies.webisTheBest // , process.env.JWTSSS)
req.user = decoded
```

JWT verification is commented out; `req.user` becomes whatever JSON object `cookie-parser` decodes from the raw cookie value, with **no signature check at all**.

**Exploitation.** This assessment logged in locally as an ordinary, non-admin test account (`alice`), confirmed she is correctly reported as non-admin, then built and sent a cookie by hand — the identical operation any attacker's browser could perform with `document.cookie`:

```
Real cookie (alice):  j:{"exp":...,"userid":2,"username":"alice"}  →  GET /IS_I_am_Good → {"IS":false}
Forged cookie:         j:{"exp":9999999999,"userid":1,"username":"admin"}
                      →  GET /IS_I_am_Good → {"IS":true}
                      →  GET /admin        → HTTP/1.1 200 (admin page served)
```

No signature, no server-side secret, and no prior admin credential were involved — the `userid` field was simply set to `1` by hand. This matches and directly reproduces the project's own documented `userid = 0`-style demonstration.

![Decoded, unsigned cookie contents inspected in Burp](./photo/Figure%209.png)

*Figure 9. The `webisTheBest` cookie, URL-decoded by Burp's Inspector panel, shown as plain, human-readable JSON (`{"exp":...,"userid":1,"username":"testv"}`) with no accompanying signature — exactly the forgeable structure exploited above.*

**Threat scenario and impact.** Any authenticated (or even unauthenticated, if an attacker constructs the cookie from scratch) client can set their own `userid` and gain full administrative access. Severity: **Critical**.

#### Modified implementation

**File:** `The APPS/web/server.js`, lines 97 (verification) and 207–210 / 275–278 (signing):

```js
const decoded = jwt.verify(req.cookies.webisTheBest, process.env.JWTSSS)
req.user = decoded
...
const bigValueToken = jwt.sign({exp: ..., userid: user.id, username: user.username}, process.env.JWTSSS)
res.cookie("webisTheBest", bigValueToken, { httpOnly: true, secure: true, sameSite: "strict", maxAge: 1000*60*60*24 })
```

![Modified cookie-verification middleware and login JWT signing, source code in VS Code](./photo/Figure%2013.png)

*Figure 13. Top: the global middleware (lines 92–107) decoding the cookie through `jwt.verify` inside a `try/catch`, falling back to `req.user = false` on any verification failure. Bottom: the `/login` route's `jwt.sign()` call and the `res.cookie(...)` options object — the manual-review evidence for both halves of the V4 fix.*

`jwt.sign()` produces a value the client cannot forge without the server's secret; `jwt.verify()` rejects any cookie whose signature does not match, so a changed `userid` is detected and the token is treated as invalid rather than trusted. `httpOnly` keeps the cookie out of reach of same-origin JavaScript (mitigating cookie theft via the XSS in Section 6.3, though not eliminating all consequences of that XSS, which can still make authenticated requests on the victim's behalf). `secure` ensures the cookie is only sent over HTTPS. `sameSite: "strict"` reduces, but — as the course materials caution — does **not** by itself replace, dedicated CSRF protection; this assessment's own Semgrep scan (Section 4.3) independently flagged the complete absence of CSRF middleware on both versions, which is consistent with that caution rather than contradicting it.

**Verification (retest).** The identical forged, unsigned cookie was replayed against the running modified application:

```
Cookie: j:{"exp":9999999999,"userid":1,"username":"admin"}
→ GET /IS_I_am_Good → {"IS":false}
→ GET /admin         → HTTP/1.1 302 Found, Location: /   (access denied)
```

The project team captured the equivalent before/after comparison directly in the browser's own cookie inspector:

![Before/after comparison of the cookie's format and Secure flag](./photo/Figure%2017.png)

*Figure 17. "Before" (vulnerable): the `webisTheBest` cookie is a readable JSON blob, 179 bytes, with the `Secure` column unchecked. "After" (modified): the cookie is now a longer (180+ byte, here truncated in the panel) signed JWT, with `Secure` now checked. `HttpOnly` and `SameSite=Strict` are present in both.*

Two further project-captured retests corroborate that invalid tokens and missing sessions are now correctly rejected on protected routes:

![GET /admin with a JWT-shaped cookie, redirected](./photo/Figure%2018.png)
![GET /my-reservations with no cookie at all, redirected](./photo/Figure%2019.png)

*Figure 18. A request to `/admin` carrying a three-part (header.payload.signature) JWT-shaped cookie still results in `302 Found → /`, consistent with `jwt.verify()` rejecting a token that does not verify (this capture does not show whether the token was expired or tampered with — only that it was correctly treated as invalid). Figure 19. A completely unauthenticated request (no `Cookie` header at all) to `/my-reservations` is also redirected — confirming the `logIN` middleware correctly blocks anonymous access to that specific route, in useful contrast with Section 6.5 below, where a structurally similar reservation-related route has no such protection.*

Status: **Fix Implemented and Verified.**

### 6.5 Missing Authorization on Reservation Update (present in both versions)

**CWE-862** (Missing Authorization).

**Affected file:** `server.js`, line 452 in the modified version (line 449 in the vulnerable version — functionally identical in both):

```js
app.post("/update_reservations:id", (req , res )=> {
    ...
    req.body.status = sanitizeHTML(req.body.status.trim() , {allowedTags: [] , allowedAttributes: {}})
    req.body.notes  = sanitizeHTML(req.body.notes.trim()  , {allowedTags: [] , allowedAttributes: {}})
    ...
    db.prepare("UPDATE reservations SET admin_notes = ? , status = ? WHERE id = ?").run(req.body.notes, req.body.status, req.params.id)
})
```

Unlike `/update_book:id` and `/create_book` (both correctly gated with `logIN, IamAdmin` — confirmed in the source and visible in Figure 6/11), this route has **no middleware of any kind**. The `status` and `notes` values are sanitized against HTML tags before storage (which is relevant to, and rules out, a stored-XSS variant of this bug — see Section 6.3's discussion), but sanitization is not authorization: anyone, authenticated or not, can call this endpoint for any reservation ID.

**Exploitation, retested live against the modified application:**

```
(as admin) GET /get_all_reservations  → status: "pending", admin_notes: "secret admin note about alice"

(no cookie at all) POST /update_reservations1
  {"status":"approved","notes":"APPROVED BY ANONYMOUS ATTACKER - no login, no cookie"}
→ HTTP/1.1 200 OK   {"success":true,"message":"update successful"}

(as admin, after) GET /get_all_reservations → status: "approved",
  admin_notes: "APPROVED BY ANONYMOUS ATTACKER - no login, no cookie"
```

The before/after admin-notes text is the attacker's own string, confirming the write genuinely succeeded with zero authentication. Severity: **High** — integrity impact on reservation records (status and administrator notes) for any user, with no authentication barrier; no confidentiality impact by itself, since the route only writes.

**Recommended defense:** add `logIN, IamAdmin` to this route (matching `/update_book:id`), and additionally verify that the acting user either owns the reservation (for user-initiated cancellation, if that is an intended feature) or is an administrator (for status/notes changes) — a bare admin check alone would be sufficient for the administrative-notes use case actually implemented here. Status: **Not Fixed** — confirmed present, unchanged, in the "modified" security-improved version.

### 6.6 Missing Object-Level Authorization (IDOR) on `/delete_reservations:id` (new finding, both versions)

**CWE-862** (Missing Authorization), specifically an Insecure Direct Object Reference (**CWE-639** — Authorization Bypass Through User-Controlled Key).

This route was not part of the project's own documentation and was found only by enumerating every route in `server.js` rather than relying on the routes already named in the project brief. It is present, unchanged, in both versions at line 536 (vulnerable) / 539 (modified):

```js
app.get("/delete_reservations:id" , logIN , (req,res) =>{
    const sqldeletestatment = db.prepare("UPDATE reservations SET  status = 'cancelled' WHERE id = ?")
    sqldeletestatment.run(req.params.id)
    res.json({ success: true })
})
```

**Root cause.** The route requires `logIN` — any valid session — but never checks that `req.user.userid` matches the `user_id` on the reservation being cancelled, and never checks `IamAdmin` either. Any authenticated user can cancel **any** reservation belonging to **any other** user, simply by guessing or enumerating the numeric `id`. It is also, independently, a state-changing action exposed on a `GET` route, which a browser will trigger automatically for an `<img>` tag, a prefetch, or a plain link — no form submission or JavaScript is even required to trigger it cross-site.

**Live reproduction, against the running modified application.** A second, unrelated test account (`bob`) was registered — a user with no reservation of his own — and used to cancel a reservation that belongs to a different user (`alice`):

```
(as admin, before) GET /get_all_reservations
  → reservation #1: user_id=2 (alice), status="approved"

(as bob — owns no reservations at all) GET /delete_reservations1
  → HTTP/1.1 200 OK   {"success":true}

(as admin, after) GET /get_all_reservations
  → reservation #1: user_id=2 (alice), status="cancelled"
```

Bob's own session has no relationship whatsoever to reservation `#1`, yet the request succeeded and changed Alice's reservation status.

**Threat scenario and impact.** Any registered user can disrupt any other user's reservations (denial of service against a specific legitimate reservation), and because the action rides on a `GET` request, it can be triggered cross-site against a logged-in victim with no interaction beyond loading a page. Integrity impact: **High**, confined to the `reservations.status` field; severity: **High** — low privilege required (any registered account), no user interaction needed beyond an active session, broad applicability (any reservation ID).

**Recommended defense:** require the acting user to either own the reservation (`req.user.userid === reservation.user_id`) or hold administrator privilege, and convert the route to `POST` (or add a CSRF-safe mechanism) since it performs a state change. Status: **Confirmed — Not Fixed** (present in both the vulnerable and the modified version; not addressed by the project's own security pass).

### 6.7 Attribute-Breakout Stored XSS via `image_url` (new finding, modified version)

**CWE-79** (stored/persistent variant).

While reviewing the remaining `innerHTML` sinks flagged in Section 6.3, the book-rendering template in `The APPS/web/views/books.html` (lines 138–150) was inspected closely:

```js
container.innerHTML = books.map(book => `
    <div class="book-card">
        <img src="${book.image_url}" alt="${book.title}">
        ...
```

`book.image_url` is written by `ValidationBook` through `sanitizeHTML(req.body.image_url.trim(), {allowedTags: [], allowedAttributes: {}})` before being stored (`server.js` line 310). That function strips disallowed **HTML tags**; it does not escape a bare quote character, because a lone `"` is not, by itself, an HTML tag. A value such as `x" onerror="alert(document.cookie)` contains no `<` or `>` at all, so it passes through unmodified.

**Live reproduction, end to end, against the running modified application.** Logged in as the admin test account and submitted exactly that string as a new book's `image_url`:

```
POST /create_book (as admin)
  {"title":"Evil Book","author":"Attacker","isbn":"9999999999999",
   "description":"test","image_url":"x\" onerror=\"alert(document.cookie)","quantity":1}
→ HTTP/1.1 200 OK   {"success":true,"message":"Add successful"}
```

Reading the value straight back out of `web.db` confirmed it was stored byte-for-byte, unsanitized: `image_url: 'x" onerror="alert(document.cookie)'`. The exact template-literal code shown above (copied verbatim from `books.html`, not re-typed from memory) was then executed in a headless DOM against this stored value:

```
Rendered <img> outerHTML:
 <img src="x" onerror="alert(document.cookie)" alt="Evil Book">
img.getAttribute('onerror'): alert(document.cookie)
onerror injected as real DOM attribute: true
```

The `src` attribute is truncated to `x` and a genuine, live `onerror` attribute is created — the same class of proof used for V3 in Section 6.3, here applied to a sink the project's own documentation does not mention.

**Threat scenario.** `/create_book` requires an administrator session, so the immediate precondition is a malicious or compromised administrator account. The resulting payload, however, is stored in the shared `books` table and rendered to **every visitor** who views the public `/books` catalog or that book's detail view — no login is required to view books. This is therefore a stored XSS with a broad, public-facing victim population, even though planting it requires admin-level write access. Severity: **Medium–High** (high potential impact and breadth of affected users; precondition of admin access lowers likelihood relative to V1–V4, which require no privilege at all).

**Recommended defense:** encode `image_url` and `title` for attribute context (not just strip tags) before interpolation — e.g., HTML-attribute-encode quote characters, or, more robustly, build the `<img>` element with `setAttribute('src', book.image_url)` rather than string concatenation, and separately validate that `image_url` is a well-formed `http(s)` URL before accepting it at write time. Status: **Confirmed — Not Fixed** (newly identified in this assessment; not covered by the project's own documentation).

### 6.8 Investigated and Not Confirmed: `IamAdmin` Logic

The project brief's own Section 8.1 describes a suspected bug in the administrator-check middleware, of the shape `if (!is_admin == 1) { return res.redirect("/") }`, reasoning that JavaScript operator precedence would make this condition always false (since `!` binds tighter than `==`, and a database row object is always truthy), so that it would never actually block a non-admin user.

This was checked directly against the real file rather than assumed correct, because the report brief explicitly warns not to silently repeat an unverified claim. The actual code, in **both** `The APPS/web vulnerability/server.js` (lines 137–144) and `The APPS/web/server.js` (lines 137–144), is:

```js
function IamAdmin (req , res ,next){
    const sqlstatment = db.prepare("SELECT is_admin FROM users WHERE id = ?")
    const is_admin = sqlstatment.get(req.user.userid)
    if (is_admin.is_admin == 0){
        return res.redirect("/")
    }
    next()
}
```

This checks the actual `is_admin` **field** of the returned row, not the row object's own truthiness — the condition the brief describes does not appear anywhere in the supplied source. This was additionally verified live, not just read: logging in as the non-admin test account `alice` and requesting `GET /admin` produced `302 Found → /` (access denied); logging in as the real `admin` account and requesting the same route produced `200 OK` with the actual admin-panel markup. A write-gated admin route (`POST /create_book`) was also tested as `alice` and likewise denied.

**Conclusion:** this specific suspected weakness is classified as **False Positive** relative to the project brief's assumption — the middleware's logic is correct in the supplied source, in both implementations, and was confirmed to behave correctly under live testing with both a privileged and an unprivileged account.

## 7. Mitigation and Verification

| Finding | Vulnerable Implementation | Modified Implementation | Retest Evidence | Final Status |
|---|---|---|---|---|
| V1 — Login SQLi / auth bypass | String-built query, `server.js:193` | Parameterized query + `bcrypt.compareSync`, `server.js:191,199` | Live retest: payload → 400; real password → 200 with JWT cookie (Section 6.1) | **Fix Implemented and Verified** |
| Plaintext password storage | `server.js:261` stores raw password | `bcrypt.hashSync`, `server.js:264` | Not separately re-exploited (superseded by V1 fix) | **Fix Implemented** |
| V2 — Search SQLi | String-built `LIKE` query, `server.js:349` | Parameterized query, `server.js:353` | Live retest + project's own Figures 14–15: UNION payload → empty result | **Fix Implemented and Verified** |
| V3 — DOM XSS (search echo) | `innerHTML` of raw query, `books.html:124-131` | `zz()` function removed | jsdom reproduction of the removed sink is no longer applicable; remaining sinks assessed separately below | **Fix Implemented (for this specific sink)** |
| V3b — Remaining `innerHTML` sinks (book list/detail) | N/A (same pattern, different data source) | Still present, `books.html:160,200`; mitigated in part by `sanitizeHTML` at write time | See Section 6.7 for a sink where the mitigation is incomplete | **Residual Risk — see 6.7** |
| V4 — Cookie manipulation | Unverified cookie, `server.js:97` | `jwt.verify`/`jwt.sign`, `server.js:97,207-210` | Live retest: forged cookie → `IS:false`, `/admin` → 302; project's Figures 17–19 | **Fix Implemented and Verified** |
| Missing auth on `/update_reservations:id` | No middleware, `server.js:449` | No middleware, `server.js:452` (unchanged) | Live retest: anonymous write succeeded (Section 6.5) | **Not Fixed** |
| Missing ownership check (IDOR) on `/delete_reservations:id` | No ownership check, `server.js:536` | No ownership check, `server.js:539` (unchanged) | Live retest: unrelated user ("bob") cancelled another user's ("alice") reservation (Section 6.6) | **Confirmed — Not Fixed** |
| `image_url` attribute-breakout XSS | N/A (new finding) | Present, `books.html:139` + `server.js:310` | Live end-to-end reproduction (Section 6.7) | **Confirmed — Not Fixed** |
| `IamAdmin` logic bug (brief's hypothesis) | Hypothesized, not present in source | Hypothesized, not present in source | Live retest with admin and non-admin accounts (Section 6.8) | **False Positive** |
| CSRF middleware | Absent | Absent | Semgrep (both scans), `server.js:11` | **Not Fixed / Residual Risk** |
| JWT secret in Git history | `The APPS/web/.env` tracked since first commit | Same | `git log --all -- '*.env'`; content-hash match between zip and remote `HEAD` (Section 8) | **Residual Risk — visibility unconfirmed** |

### Recommended defenses, summarized

| Security Area | Recommended Defense |
|---|---|
| Login SQL Injection | Parameterized SQL and a separate, constant-time password comparison (bcrypt) — both already present in the modified version |
| Password Storage | bcrypt hashing at registration — already present |
| Search SQL Injection | Parameterized SQL — already present |
| DOM-based / stored XSS | Replace string-built `innerHTML` with `textContent`/`createElement`, or context-appropriate encoding (HTML-body encoding **and** HTML-attribute encoding, not just tag-stripping) |
| Cookie Manipulation | JWT signing and server-side signature verification — already present |
| Cookie Security | `httpOnly`, `secure`, `sameSite` — already present |
| Reservation Updates | Add `logIN, IamAdmin` to `/update_reservations:id` |
| Reservation Cancellation (IDOR) | Add an ownership check (or `IamAdmin`) to `/delete_reservations:id`, and convert it from `GET` to a state-changing method |
| CSRF | Add an explicit CSRF-token or double-submit-cookie check; `SameSite=Strict` reduces but does not replace this |
| Secret Management | Rotate `JWTSSS`, add `.env` to `.gitignore`, remove the tracked file from Git history, and confirm the repository's own public/private visibility setting directly on GitHub |

## 8. Residual Risks and Limitations

- **Missing authorization on `/update_reservations:id`** (Section 6.5) is one of the most significant residual risks: it was not addressed by the security pass that fixed V1–V4, and it allows unauthenticated tampering with reservation records.
- **Missing object-level authorization (IDOR) on `/delete_reservations:id`** (Section 6.6) is equally significant and was found only by enumerating every route in `server.js` rather than relying on the project's own documented route list — any registered user, not just the reservation's owner, can cancel any other user's reservation, and the action is exposed on a `GET` route.
- **The `image_url` attribute-breakout stored XSS** (Section 6.7) remains exploitable by any administrator account (or anyone who compromises one), with impact to every visitor of the public catalog.
- **No CSRF protection.** Both this assessment's own Semgrep scan and the project's own `--config-auto` run flag the absence of CSRF middleware on both versions. `sameSite: "strict"` reduces exposure for most browsers but is not a substitute for an explicit token-based defense, and should not be represented as complete CSRF protection.
- **`.gitignore` does not exclude `.env`.** The file `.gitignore` in the repository root excludes `node_modules/`, `*.log`, and `**/web.db`, among others, but has no rule for `.env`. Combined with the finding below, this is a straightforward, low-effort fix.
- **JWT secret tracked in Git history — exposure not fully confirmed.** `git log --all -- '*.env'` against a fresh clone of `https://github.com/adel511CY/Digital-Library` (HEAD at commit `883577d`, matching the supplied ZIP archive exactly on a full `diff -r` comparison of `The APPS/`) shows the secrets file has been tracked since the project's very first two commits. Content-hash comparison (hashing only the secret value, never printing it in this report) confirms the value in the ZIP's `.env` is identical to the value committed to the repository. Whether the GitHub repository itself is public could **not** be confirmed from this environment — an unauthenticated request to the GitHub REST API for this repository returned `403 Forbidden`, which is consistent with either a private repository or simply an API rate/auth restriction, and is not conclusive either way. **This is reported as a limitation, not a confirmed public exposure.** The team should check the repository's visibility setting directly in GitHub and, regardless of the answer, rotate the secret and scrub it from history, since a secret that has ever been committed should be treated as compromised.
- **Limitations of this assessment's own automated scan.** The offline Semgrep rule mirror used here (Section 4) is a different, non-identical configuration from the project's own registry-based `p/javascript` scan, so finding counts between the two are not directly comparable; both are reported with their own source clearly labeled.
- **Limitations of dynamic testing.** All dynamic testing in this report was performed locally against the application running on `localhost`, seeded with disposable test accounts and one planted test reservation. No production data, and no publicly hosted instance of this application, was accessed at any point.
- **Image evidence.** The supplied archive's `analysis/photo/` directory contains **19** screenshots (`Figure 1`–`Figure 11`, `Figure 13`–`Figure 20`; there is no `Figure 12`), not the 20 referenced in the assignment brief. All 19 were individually inspected and are accounted for in this report (Appendix B lists any not given a dedicated caption). A separate, older `photo/` folder at the repository root (11 images, `the 1.png`–`the 11.png`) was identified but, per the project's own instruction not to confuse it with the authoritative evidence set, was not used as a source of captioned figures in this report.

## 9. Conclusion

This assessment confirmed, by direct reproduction against the running application rather than by trusting the project's own write-up, that all four originally documented vulnerabilities (login SQL injection, search SQL injection, DOM-based XSS, and unsigned-cookie privilege escalation) are real, were exploitable in the vulnerable implementation, and are genuinely fixed in the modified implementation — each retested with the same or an equivalent payload and an observed, quoted before/after change in behavior.

The modified version is not fully secure, however. Three further issues were confirmed through direct, live testing: an authentication-and-authorization gap on the reservation-update endpoint that lets anyone tamper with reservation records; a missing ownership check on the reservation-cancellation endpoint that lets any registered user cancel any other user's reservation; and an attribute-context XSS vector in the book `image_url` field that the existing tag-stripping sanitization does not cover. A fourth suspected weakness, drawn from the assignment brief's own hypothesis about the `IamAdmin` middleware, was tested directly and found **not** to be present in the actual source — an outcome worth stating plainly, since treating an unverified assumption as fact would itself have been a reporting error of the kind this course is meant to train students out of.

**Recommended next steps:** add authorization middleware to `/update_reservations:id`; add an ownership check to `/delete_reservations:id`; fix the `image_url` attribute-encoding gap; add CSRF-token protection; move `JWTSSS` out of the tracked repository and rotate it; and confirm the repository's actual visibility setting.

## References

1. MITRE, "CWE-89: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')." [Online]. Available: https://cwe.mitre.org/data/definitions/89.html
2. MITRE, "CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')." [Online]. Available: https://cwe.mitre.org/data/definitions/79.html
3. MITRE, "CWE-565: Reliance on Cookies without Validation and Integrity Checking." [Online]. Available: https://cwe.mitre.org/data/definitions/565.html
4. MITRE, "CWE-862: Missing Authorization." [Online]. Available: https://cwe.mitre.org/data/definitions/862.html
5. MITRE, "CWE-639: Authorization Bypass Through User-Controlled Key." [Online]. Available: https://cwe.mitre.org/data/definitions/639.html
6. MITRE, "CWE-256: Plaintext Storage of a Password." [Online]. Available: https://cwe.mitre.org/data/definitions/256.html
7. MITRE, "CWE-540: Inclusion of Sensitive Information in Source Code Repository." [Online]. Available: https://cwe.mitre.org/data/definitions/540.html
8. OWASP, "SQL Injection Prevention Cheat Sheet." [Online]. Available: https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html
9. OWASP, "DOM based XSS Prevention Cheat Sheet." [Online]. Available: https://cheatsheetseries.owasp.org/cheatsheets/DOM_based_XSS_Prevention_Cheat_Sheet.html
10. OWASP, "Web Security Testing Guide." [Online]. Available: https://owasp.org/www-project-web-security-testing-guide/
11. Semgrep, Inc., "Semgrep Documentation." [Online]. Available: https://semgrep.dev/docs/
12. OpenJS Foundation, "Express.js — Production Best Practices: Security." [Online]. Available: https://expressjs.com/en/advanced/best-practice-security.html
13. M. Jones, J. Bradley, and N. Sakimura, "JSON Web Token (JWT)," IETF RFC 7519, May 2015. [Online]. Available: https://www.rfc-editor.org/rfc/rfc7519

## Appendix A — Detailed Vulnerability Assessment Table

| ID / CWE | Tool & Validation Evidence | Threat / Impact / Severity | Defense & Verification |
|---|---|---|---|
| V1 / CWE-89, CWE-287 | Semgrep `tainted-sql-string` (`server.js:193`); live retest (bypass → fix confirmed) | Unauthenticated full auth bypass, incl. admin. Confidentiality/Integrity: High. No privilege or user interaction required. **Critical** | Parameterized query + bcrypt — Fix Implemented and Verified |
| Plaintext passwords / CWE-256 | Manual code review (`server.js:257-261` vs `264`) | Credential exposure if DB leaked. **Medium–High** | bcrypt hashing — Fix Implemented |
| V2 / CWE-89 | Semgrep `tainted-sql-string` (`server.js:349`); live retest (UNION leak → fix confirmed) | Unauthenticated extraction of arbitrary table data (demonstrated: `reservations.admin_notes`). Confidentiality: High. **Critical** | Parameterized query — Fix Implemented and Verified |
| V3 / CWE-79 (DOM) | jsdom parse-level reproduction; project screenshot (real-browser execution, Figure 8) | Arbitrary JS execution in victim browser via search field. **High** | Sink removed for this input — Fix Implemented (this sink only) |
| V4 / CWE-565, CWE-287 | Semgrep `session-fixation`/`cookies-secure-missing` (project scan, Figure 4); live retest (forged cookie → fix confirmed) | Unauthenticated privilege escalation to administrator by hand-editing a cookie. **Critical** | Signed, verified JWT + secure cookie flags — Fix Implemented and Verified |
| Missing auth on `/update_reservations:id` / CWE-862 | Manual code review; live retest (anonymous write succeeded in the modified version) | Unauthenticated tampering with any reservation's status/notes. Integrity: High. **High** | Add `logIN, IamAdmin` — **Not Fixed** |
| Missing ownership check on `/delete_reservations:id` / CWE-862, CWE-639 | Full route enumeration of `server.js`; live retest with two unrelated accounts ("bob" cancelling "alice"'s reservation) | Any authenticated user can cancel any other user's reservation via a `GET` request. Integrity: High. **High** | Add ownership/admin check; convert off `GET` — **Confirmed, Not Fixed** |
| `image_url` attribute XSS / CWE-79 | Manual code review + live end-to-end reproduction (stored value → jsdom render → live `onerror` attribute) | Stored XSS affecting all visitors to the public catalog; requires an admin account to plant. **Medium–High** | Attribute-context encoding / `setAttribute` — **Confirmed, Not Fixed** |
| `IamAdmin` logic (brief's hypothesis) | Manual code review of actual source; live retest with admin and non-admin accounts | N/A — hypothesis not present in source | **False Positive** |
| CSRF middleware | Semgrep (both this assessment's scan and the project's own scan) flag its absence on both versions | Depends on what state-changing actions a forged cross-site request could trigger while `sameSite=strict` does not apply (e.g., top-level navigations) | Add explicit CSRF token — **Residual Risk** |

## Appendix B — Additional Evidence and Image-Usage Notes

- All 19 images in `analysis/photo/` were opened and visually inspected; none were assumed from filename alone. All 19 are embedded at their first relevant use throughout this report (Figures 1–11, 13–20); none were found duplicated-and-discarded, irrelevant, or unclear enough to exclude, apart from the Figure 3/Figure 5 near-duplicate pair noted below.
- Figures 3 and 5 are a duplicate pair (same test, two captures) — documented once in Section 6.1 rather than captioned separately, per Section 10.6 of the assignment brief.
- No screenshot in the supplied set shows the V1 bypass response itself succeeding; this gap is filled with this assessment's own quoted request/response evidence (Section 6.1) rather than left unaddressed.
- The repository's separate, older `photo/` folder (`the 1.png` – `the 11.png`, at the repository root, not inside `analysis/`) was identified and reviewed for context but was not used as a source of captioned figures, per the assignment brief's explicit instruction not to confuse it with the authoritative `analysis/photo/` set.
- **Path note.** The assignment brief assumes the 20 screenshots sit directly inside `analysis/`. In the actual supplied archive, they are one level down, in `analysis/photo/`. This report's image links use the path that actually resolves from this file's real location (`./photo/Figure%20N.png`) rather than a flat `./Figure%20N.png` path that would render as broken links on GitHub; no image file was moved, renamed, or copied to force a different layout. The one image that *was* added to this assessment — the attack-surface diagram in Section 3.3 — is a separately produced diagram (not one of the original 19 screenshots) and is saved directly inside `analysis/` as `attack-surface-diagram.jpg`, consistent with the brief's own instruction for a separately generated diagram.
- **Viewing the images.** All image links in this file are relative paths (`./photo/...`, `./attack-surface-diagram.jpg`). They render correctly when this file is opened from inside the full project folder — e.g., on GitHub after this `analysis/` folder is pushed alongside the rest of the repository, or in an editor/Markdown previewer (VS Code, Typora, Obsidian) opened at the project root — because the images physically sit next to this file at those relative locations. Opening only the standalone `.md` file by itself, outside that folder structure, will show broken image links, since the images are not embedded inside the text file itself (this report intentionally does not embed screenshots as Base64, per the assignment brief's own instruction not to do so). The companion ZIP archive provided alongside this report contains the whole project with this file and every image already in their correct relative positions, so opening it from there will display every figure.
- **Sensitive-value handling.** No screenshot in the supplied set displays the JWT signing secret (`JWTSSS`) itself; the cookie values shown (Figures 9, 17, 18) are session tokens for disposable test accounts (e.g., `testv`, `alice`), not production credentials, and are left unredacted on that basis. The actual secret value was never printed or stored in this report at any point, including during the Git-history check in Section 8.

## Appendix C — Team Contributions

| Member | Contribution |
|---|---|
| عادل عوض المقاطي (Adel Almquti) — 2440382 | [Insert specific contribution] |
| [Insert Name] | [Insert specific contribution] |
| [Insert Name] | [Insert specific contribution] |
