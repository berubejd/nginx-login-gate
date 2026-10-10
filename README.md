# nginx-login-gate

A small nginx reverse proxy that puts a real login page in front of any web service. It's for apps that have no auth of their own, and for prototypes where you want to skip building auth for now.

- **Styled login page**: light and dark mode, works on mobile, no browser popup
- **Multiple users**: `AUTH_USERS=alice:pw1,bob:pw2`
- **Cookie sessions**: sign in once and stay signed in (7 days by default)
- **Your app knows who's signed in**: every request carries an `X-Forwarded-User` header
- **Scripts still work**: `curl -u alice:pw1 ...` is accepted too (you can turn this off)
- **Real visitor IP**: passed to your app in `X-Real-IP`, and used for logs and login rate limiting
- **WebSockets**: supported
- **One container**: just nginx, with its built-in JavaScript module (njs)

Based on [biw/railway-nginx-password-auth](https://github.com/biw/railway-nginx-password-auth). That project gets the credit for the Railway-friendly proxy setup (DNS resolver detection, upstream TLS, WebSockets).

## How it works

1. A request comes in without a valid session.
   - A browser gets redirected to `/_gate/login?next=<where you were going>`.
   - Anything else (API calls, `fetch`, POSTs) gets a plain `401` JSON response.
2. You sign in. The gate sets a signed, `HttpOnly` cookie and sends you back to where you started.
3. Each later request checks the cookie and is passed through to `ORIGIN` with `X-Forwarded-User: <username>`.

Sessions are signed with `SESSION_SECRET`. A session stops working when:
- it expires (`SESSION_HOURS`)
- that user is removed from `AUTH_USERS`, or their password changes
- `SESSION_SECRET` changes (this signs everyone out)

## Environment variables

| Variable | Required | Default | What it does |
| --- | --- | --- | --- |
| `ORIGIN` | ✅ | | The service to protect, e.g. `http://myapp.railway.internal:3000` |
| `AUTH_USERS` | ✅* | | Comma-separated `username:password` pairs, e.g. `alice:pw1,bob:pw2` |
| `SESSION_SECRET` | Strongly recommended | random at startup | Signs session cookies. Use 32+ random characters. If you leave it unset, everyone is signed out on every redeploy. |
| `SESSION_HOURS` | | `168` (7 days) | How long a sign-in lasts |
| `ALLOW_BASIC_AUTH` | | `true` | Also accept an `Authorization: Basic` header, for scripts and CLI tools |
| `TRUST_PROXY_HEADERS` | | `true` | Take the visitor's IP and scheme from the proxy's `X-Forwarded-For` and `X-Forwarded-Proto` headers (see [Client IP](#client-ip)). Set to `false` if the gate is reachable directly, without a proxy in front. |
| `LOGIN_TITLE` | | `Private service` | Heading on the login page |
| `LOGIN_SUBTITLE` | | `Sign in to continue` | Line under the heading |
| `LOGIN_ACCENT` | | `#4f46e5` | Button and highlight color (hex) |
| `ALLOW_NO_AUTH` | | | Set to `true` to run without any users (plain proxy) |

\* `BASIC_AUTH` from the original project still works as an alias for `AUTH_USERS`, so it can drop in as a replacement.

Generate a secret with:

```bash
openssl rand -base64 48
```

### User rules

- Usernames can use letters, digits, and `. _ @ + -`.
- Passwords can contain anything except a comma. Colons are fine: `bob:p@ss:word` means the password is `p@ss:word`.
- Spaces around each pair are trimmed, so `alice:pw1, bob:pw2` works.

## Client IP

On Railway, every connection to the gate comes from Railway's edge proxy, not from the visitor. The edge puts the visitor's IP in `X-Forwarded-For`.

With `TRUST_PROXY_HEADERS=true` (the default), nginx takes the visitor's IP from the **last** entry of that header, which is the one the proxy added. That IP is used for:

- `X-Real-IP` sent to your app
- the access log
- the login rate limit, so each visitor gets their own limit

**In your app, read `X-Real-IP`.** Don't use the first entry of `X-Forwarded-For`, because a visitor can put anything there.

Your app also receives `X-Forwarded-For` with the full chain, ending in the proxy hop that connected to the gate. Example:

```
Visitor sends:          X-Forwarded-For: 6.6.6.6          (fake)
Railway edge adds:      X-Forwarded-For: 6.6.6.6, 203.0.113.7
Your app receives:      X-Real-IP: 203.0.113.7
                        X-Forwarded-For: 6.6.6.6, 203.0.113.7, <railway proxy>
```

Your app also receives `X-Forwarded-Proto` set to the scheme the visitor used, `https` or `http`. The gate reads the last entry of that header, the one the proxy added, and forwards that single value. The gate's own session cookie gets `Secure` from the same value.

```
Visitor uses HTTPS
Railway edge sends:     X-Forwarded-Proto: https
Your app receives:      X-Forwarded-Proto: https
```

Trusting these headers is safe only because nobody can reach the gate except through the proxy. If you run the gate with no proxy in front, set `TRUST_PROXY_HEADERS=false`. The app then receives the gate's own connection scheme (`http` on port 80), and a visitor cannot claim the request was HTTPS.

Railway hasn't published a firm rule on whether its edge replaces or appends to an incoming `X-Forwarded-For` or `X-Forwarded-Proto`. Taking the last entry is correct either way. After your first deploy, it's worth checking once what your app receives.

## Reserved paths

Everything under `/_gate/` belongs to the gate and is never passed to your app:

| Path | Purpose |
| --- | --- |
| `/_gate/login` | Login page |
| `/_gate/logout` | Signs you out and returns to the login page |

## Railway setup

1. Deploy this repo as a new service.
2. Set `ORIGIN` to your app's private address, e.g. `http://myapp.railway.internal:3000`.
3. Set `AUTH_USERS` and `SESSION_SECRET`.
4. Give this service the public domain. Remove the public domain from the app itself, so the only way in is through the gate.

## Local testing

```bash
docker build -t nginx-login-gate .
docker run -p 8080:80 \
  -e ORIGIN="http://host.docker.internal:3000" \
  -e AUTH_USERS="alice:pw1,bob:pw2" \
  -e SESSION_SECRET="$(openssl rand -base64 48)" \
  -e LOGIN_TITLE="My Prototype" \
  nginx-login-gate
```

Then open http://localhost:8080.

Script access:

```bash
curl -u alice:pw1 http://localhost:8080/api/things
```

## Security notes

- Passwords live in environment variables, the same as the original project. That's fine for a personal gate. It isn't a user database.
- The cookie is `HttpOnly` and `SameSite=Lax`, and it gets `Secure` when the scheme forwarded to your app is `https`.
- Login attempts are limited to 10 per minute per visitor IP, with a small burst allowance. This needs `TRUST_PROXY_HEADERS=true` behind a proxy. Otherwise every visitor shares the proxy's IP and therefore one limit.
- `X-Forwarded-User` is always set by the gate. A value sent by the client is overwritten (or removed), so it can't be spoofed.
- When a script signs in with Basic auth, that `Authorization` header is removed before the request reaches your app, so the app never sees gate passwords. Other `Authorization` values (like a Bearer token for your app's own API) pass through unchanged.
- The gate never sends a `WWW-Authenticate` challenge, so browsers never show the native popup. CLI tools must send credentials up front (`curl -u` does).
- Upstream `401` responses from your app pass through unchanged.

## Files

| File | Purpose |
| --- | --- |
| `Dockerfile` | `nginx:alpine` plus bash and envsubst |
| `docker-entrypoint.sh` | Checks settings, writes the session secret, renders the config |
| `nginx.conf` | Loads njs and passes the gate's env vars through to it |
| `nginx.conf.template` | The proxy server block |
| `gate.js` | Session, login, and Basic auth logic (njs) |
| `login.html` | The login page template |

## License

MIT. See [LICENSE](LICENSE).
