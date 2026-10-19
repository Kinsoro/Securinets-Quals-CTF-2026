# NYOOM — From Reconnaissance to Flag

**Competition:** Securinets Quals CTF 2026  
**Category:** Web  
**Difficulty:** Hard  
**Team:** APT212  
**Target tested:** `http://3ff3ebf25005.inst1.securinets.tn:8080`

> **Result:** The successful remote run received `Securinets{50a7326cda75765f0b8d6eafeed0ffed}` at the exploit's callback endpoint. The local Docker environment used a deliberately different decoy flag: `Securinets{if_u_submit_this_u_r_disqualified}`.

## 1. Summary

NYOOM combines several weaknesses across an Express application, a Varnish reverse proxy, and a Puppeteer reporting bot.

The successful exploit used the following chain:

1. Register a normal account and store attacker-controlled HTML in its profile biography.
2. Use CSS attribute selectors as a side channel to test three-character substrings of the dashboard's CSP nonce.
3. Collect the callbacks and reconstruct the 32-character hexadecimal nonce from overlapping trigrams.
4. Keep a stylesheet response pending so the first dashboard load does not proceed past the relevant parser-blocking stylesheet until the second-stage biography is ready.
5. Release the stylesheet. The dashboard's profile loader obtains the updated biography, which contains an iframe with a script carrying the recovered nonce.
6. From that script, request `/Fragments/session-info`. The capitalized path bypasses Varnish's lowercase-only path check but still matches the Express route.
7. Read the session-derived value from the fragment and send it to the callback server.

The successful exploit used the direct capitalized fragment route. ESI was also tested locally and confirmed to be active on `/preview`, but that separate test is not evidence that ESI was required for the successful remote run.

## 2. Architecture and source review

The source review focused on three components:

- **Express application** — account creation, profile storage, dashboard rendering, CSP generation, and the session-information endpoint.
- **Varnish** — path filtering and ESI response processing.
- **Puppeteer reporting bot** — launches a headless browser, installs an administrator session cookie, visits a submitted URL, waits, and then closes the browser.

The key application behavior was:

- `POST /login` creates a user and issues a normal session cookie.
- `POST /profile` stores the user's biography after only truncating it to 8,000 characters; it does not sanitize it as HTML.
- `GET /dashboard` places biography content in the page and creates a random CSP nonce.
- The dashboard's profile loader later fetches `/profile` and assigns the biography to `innerHTML`.
- `GET /fragments/session-info` places a recognized session-cookie value in the fragment's `data-session` attribute.
- The bot visits a URL with its privileged session cookie present.

### The session value and the flag

In the supplied challenge source, the sessions map associates the flag value with the administrator identity, and the bot uses the configured `ADMIN_SESSION` value as its session cookie. The fragment handler returns the cookie value itself when it is recognized by the sessions map. In the remote deployment, the privileged session value was therefore the value the exploit recovered.

This is different from the ordinary session cookie created when the exploit registers its own account. The script's logged “session cookie captured” message refers to the attacker's account, not the bot's administrator cookie.

## 3. Finding 1 — HTML injection in the biography

The biography was not consistently rendered as plain text. The dashboard included biography markup in the HTML, and its later profile refresh assigned the stored value to `innerHTML`.

A raw `<script>` element inserted by the later `innerHTML` update did not execute in the local browser test. That negative result was useful: the ability to inject HTML alone was not enough to bypass the CSP or execute an arbitrary script.

The viable route required a script element in a parsing context that would be permitted by the dashboard's CSP, with the correct nonce.

## 4. Finding 2 — CSP nonce side channel through CSS

The dashboard generates a nonce using 16 random bytes encoded as hexadecimal, which produces a 32-character hexadecimal string. Its CSP meta element includes a directive of the form:

```html
<meta http-equiv="Content-Security-Policy"
      content="script-src 'nonce-<random-hex-value>'">
```

Rather than guessing the entire value, the exploit tested three-character hexadecimal strings against the CSP meta element's `content` attribute using CSS attribute selectors. A matching rule caused the browser to request a unique callback path from the external listener. That let the listener record which trigrams occurred in the nonce.

There are `16^3 = 4096` possible three-character hexadecimal strings. The exploit generated a stylesheet covering these candidates. During the successful run, the listener served `leak.css` (reported size: 696,417 bytes) and collected 30 unique trigrams.

A 32-character string has 30 overlapping three-character windows. For example, the trigrams `abc`, `bcd`, and `cde` can be joined as `abcde`. The exploit used overlap-based graph search to reconstruct candidates from the observed trigrams. The successful run reported 465 search nodes visited and one candidate nonce.

The terminal output did not print the nonce itself. Accordingly, this write-up records the reported reconstruction result without claiming a specific nonce value.

## 5. Timing the two stages with `slow.css`

The first biography loaded the generated leak stylesheet and a second stylesheet whose response the callback server intentionally kept open.

This pending stylesheet acted as a timing gate. While the browser was waiting on the stylesheet, the exploit collected the CSS callbacks and updated the biography with the second-stage content. It then released the pending response, allowing the dashboard's remaining load logic to continue and obtain the updated biography.

This sequencing mattered because the nonce was not available when the first-stage biography was prepared. The exploit needed to gather the nonce evidence first, store the second stage, and only then let the browser continue.

The successful log confirms the sequence:

- `slow.css requested; holding response open`
- `Collected 30 unique nonce trigrams`
- `candidate nonce count: 1`
- `Phase-2 bio set using 1 nonce candidates`
- `Released slow.css`

## 6. Finding 3 — Varnish and Express interpret path capitalization differently

The relevant Varnish rule was:

```vcl
if (req.url ~ "^/fragments/" && req.esi_level == 0) {
    return (synth(403, "Internal only"));
}
```

This regular expression matches the lowercase `/fragments/` prefix. It is case-sensitive. Express, meanwhile, matches route paths case-insensitively by default.

That created a mismatch between the proxy's access-control check and the application's route matching:

- `/fragments/session-info` matched Varnish's restriction and was rejected as a direct request.
- `/Fragments/session-info` did not match the lowercase Varnish expression, but still reached the Express route.

A local manual test of the capitalized path returned `200 OK` with `data-session="anonymous"` when no valid session cookie was supplied. This demonstrated the routing bypass, not flag disclosure on its own.

## 7. Second stage — Read the privileged fragment and exfiltrate the value

After reconstructing the nonce, the exploit updated the biography with a second-stage payload. The payload created an iframe using `srcdoc` and placed the recovered nonce on the script element inside it.

The script then:

1. Requested `/Fragments/session-info` from the same origin.
2. Parsed the fragment and read its `data-session` attribute.
3. Sent the value to the external callback server using an image request.

Because the browser belonged to the reporting bot, the fragment request carried the bot's privileged session cookie. The endpoint returned the recognized cookie value in the HTML fragment, and the callback listener recorded the recovered flag.

The key point is that no single finding was sufficient by itself. HTML injection provided the content control, the CSS side channel recovered the nonce, the Varnish mismatch exposed the fragment route, and the bot's privileged browser context supplied the sensitive session value.

## 8. ESI investigation — a separate local finding

The source also exposed a separate ESI behavior:

- Varnish enabled ESI processing for responses from `/preview`.
- The preview handler included user-controlled template content in its response without removing ESI directives.
- A local test submitted an ESI include and observed the fetched fragment appear between test markers instead of the directive remaining literal text.

This confirmed that ESI processing worked in the local environment. However, the test returned an anonymous session value and did not retrieve the remote flag. It is documented here as a separate finding, not as a required step in the confirmed successful `nyoom_exploit2.js` run, which used the capitalized fragment route directly.

## 9. Evidence and what it proves

| Evidence | Supported conclusion | What it does **not** prove |
|---|---|---|
| Local lowercase fragment request rejected; capitalized request returned `200 OK` and `anonymous` | The Varnish/Express capitalization mismatch is exploitable in the local setup. | This test alone does not disclose the remote administrator session or flag. |
| Local `/preview` test returned the included fragment | Varnish processed ESI in the local preview response. | It does not establish that ESI was used in the successful remote exploit. |
| Successful exploit log reports 30 unique trigrams, 465 graph-search nodes, and one candidate | The exploit collected nonce-related observations and its reconstruction routine reported a single candidate. | The log does not expose the nonce string, so it cannot independently verify the exact candidate value. |
| The remote run printed the flag after a `[FLAG CALLBACK]` event | The callback listener received the remote flag during the successful run. | The transcript alone is not a packet capture or a complete record of every browser request. |
| The report endpoint returned HTTP 200 with the visited dashboard URL | The bot accepted the report and reported visiting the requested dashboard. | HTTP 200 alone would not prove exploit success; the flag callback is the stronger end-to-end evidence. |

### Successful remote run

The confirmed run used `nyoom_exploit2.js` with the target and callback URL configured for that run. The relevant terminal output was:

```text
[+] Attacker listener on 0.0.0.0:9999
[+] Registering challenge user: nyoom4c727a
[+] Registered; session cookie captured (56 chars)
[+] Phase-1 bio set.
[+] Reporting dashboard to bot: http://edge:8080/dashboard?u=nyoom4c727a
[+] Served leak.css (696417 bytes)
[*] slow.css requested; holding response open.
[+] Collected 30 unique nonce trigrams
[+] Trigram graph search visited 465 nodes; candidate nonce count: 1
[+] Phase-2 bio set using 1 nonce candidates
[+] Released slow.css

[FLAG CALLBACK] Securinets{50a7326cda75765f0b8d6eafeed0ffed}

[FLAG] Securinets{50a7326cda75765f0b8d6eafeed0ffed}

[+] Report endpoint responded HTTP 200:
{"ok":true,"visited":"http://edge:8080/dashboard?u=nyoom4c727a"}
```

The flag above is from the remote callback shown in the successful run. The local Docker decoy flag is not the submitted result.

## 10. Root causes and mitigations

### Unsafe HTML rendering
**Root cause:** User-controlled biography data reaches an HTML sink.  
**Mitigation:** Render user content as text by default. If rich text is required, sanitize it with a maintained sanitizer and a strict allowlist.

### CSS side channel and broad resource permissions
**Root cause:** The CSP's nonce-based `script-src` did not sufficiently restrict style and image loading, allowing CSS to trigger observable requests.  
**Mitigation:** Apply a restrictive policy using `default-src` and explicit `style-src`, `img-src`, `connect-src`, and related directives. Avoid putting secrets in DOM attributes.

### Inconsistent path validation
**Root cause:** The proxy and application apply different path-matching rules.  
**Mitigation:** Normalize paths consistently and enforce authorization in the application as well as at the proxy.

### ESI on user-controlled responses
**Root cause:** ESI processing is enabled for a response containing user-controlled template text.  
**Mitigation:** Do not process ESI in untrusted responses. If ESI is needed, strictly control which backend responses and include targets are eligible.

### Privileged reporting bot
**Root cause:** The bot opens user-influenced content while holding a privileged session.  
**Mitigation:** Use a least-privileged identity, isolate browser contexts, restrict destinations and routes, and never reuse a flag as an authentication credential.

### Session-derived values exposed in HTML
**Root cause:** The fragment makes a recognized session-cookie value observable in page content.  
**Mitigation:** Never expose session identifiers, authentication secrets, or flag-derived values in HTML responses.

## 11. Version and reproducibility note

The successful terminal transcript identifies `nyoom_exploit2.js`. A separately saved `nyoom_exploit.js` variant also exists, but the two should not be described as identical without a source-level comparison. This write-up attributes the confirmed result to the version used in the successful run and keeps the local ESI experiment separate from that evidence.

The historical quick-tunnel URL used for the successful run is intentionally not provided as a reusable endpoint; temporary tunnel URLs expire. A fresh run requires a currently active callback URL and a reachable challenge instance.

## 12. Final result

The remote flag received during the successful exploit run was:

```text
Securinets{50a7326cda75765f0b8d6eafeed0ffed}
```

The central lesson is the composition of weaknesses: unsafe profile HTML, a CSS-based nonce side channel, inconsistent path validation between Varnish and Express, and a privileged browser bot. The report distinguishes the successful remote chain from exploratory local ESI testing so that each conclusion stays within the evidence available.
