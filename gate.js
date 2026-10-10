// nginx-login-gate: cookie-session login in front of any upstream, in njs.
//
// Flow:
//   - Every proxied request evaluates $gate_user (js_set -> user()).
//     It is the username from a valid session cookie or, if enabled,
//     a valid Basic auth header. Empty string means "not authenticated".
//   - nginx returns 401 when $gate_user is empty; error_page sends that
//     to unauthorized(), which redirects browsers to the login page and
//     gives API/CLI clients a plain 401.
//   - login() renders the page (GET) and checks credentials (POST).
//
// Session cookie: base64url(JSON {u, e}) "." HMAC-SHA256 signature.
// The signature also covers the user's current password, so changing or
// removing a user in AUTH_USERS invalidates that user's sessions.

import fs from 'fs';
import qs from 'querystring';
import crypto from 'crypto';

const COOKIE = 'gate_session';
const SECRET_FILE = '/etc/nginx/gate/secret';
const TEMPLATE_FILE = '/etc/nginx/gate/login.html';
const DEFAULT_ACCENT = '#4f46e5';

// ---------- config ----------

function env(name, fallback) {
    const v = process.env[name];
    return (v === undefined || v === '') ? fallback : v;
}

function secret() {
    return fs.readFileSync(SECRET_FILE, 'utf8').trim();
}

function sessionSeconds() {
    const hours = parseInt(env('SESSION_HOURS', '168'), 10);
    return (hours > 0 ? hours : 168) * 3600;
}

// AUTH_USERS="alice:pw1,bob:pw2" (BASIC_AUTH accepted as an alias)
function users() {
    const raw = env('AUTH_USERS', env('BASIC_AUTH', ''));
    const map = {};
    raw.split(',').forEach(function (pair) {
        pair = pair.trim();
        const i = pair.indexOf(':');
        if (i > 0 && i < pair.length - 1) {
            map[pair.slice(0, i)] = pair.slice(i + 1);
        }
    });
    return map;
}

// ---------- crypto helpers ----------

function hmac(key, data) {
    return crypto.createHmac('sha256', key).update(data).digest('base64url');
}

function checkPassword(username, password) {
    const all = users();
    const key = secret();
    // Compare HMACs rather than raw strings so timing says nothing
    // useful about the stored password.
    const given = hmac(key, 'pw:' + password);
    if (!Object.prototype.hasOwnProperty.call(all, username)) {
        hmac(key, 'pw:dummy'); // keep timing similar for unknown users
        return false;
    }
    return given === hmac(key, 'pw:' + all[username]);
}

function sign(payload, password) {
    return hmac(secret(), 'session:' + payload + ':' + password);
}

function issueToken(username) {
    const body = JSON.stringify({ u: username, e: Math.floor(Date.now() / 1000) + sessionSeconds() });
    const payload = Buffer.from(body).toString('base64url');
    return payload + '.' + sign(payload, users()[username]);
}

function verifyToken(token) {
    const dot = token.indexOf('.');
    if (dot < 1) return '';
    const payload = token.slice(0, dot);
    const sig = token.slice(dot + 1);
    let data;
    try {
        data = JSON.parse(Buffer.from(payload, 'base64url').toString());
    } catch (e) {
        return '';
    }
    if (!data || typeof data.u !== 'string' || typeof data.e !== 'number') return '';
    if (data.e < Math.floor(Date.now() / 1000)) return '';
    const all = users();
    if (!Object.prototype.hasOwnProperty.call(all, data.u)) return '';
    return sig === sign(payload, all[data.u]) ? data.u : '';
}

// ---------- request helpers ----------

function readCookie(r, name) {
    const header = r.headersIn.Cookie;
    if (!header) return '';
    const parts = header.split(';');
    for (let i = 0; i < parts.length; i++) {
        const p = parts[i].trim();
        if (p.indexOf(name + '=') === 0) return p.slice(name.length + 1);
    }
    return '';
}

function sessionUser(r) {
    const token = readCookie(r, COOKIE);
    return token ? verifyToken(token) : '';
}

function basicUser(r) {
    if (env('ALLOW_BASIC_AUTH', 'true') !== 'true') return '';
    const h = r.headersIn.Authorization || '';
    if (h.slice(0, 6).toLowerCase() !== 'basic ') return '';
    let decoded;
    try {
        decoded = Buffer.from(h.slice(6).trim(), 'base64').toString();
    } catch (e) {
        return '';
    }
    const i = decoded.indexOf(':');
    if (i < 1) return '';
    const name = decoded.slice(0, i);
    return checkPassword(name, decoded.slice(i + 1)) ? name : '';
}

function isHttps(r) {
    // Same value forwarded upstream as X-Forwarded-Proto.
    return r.variables.gate_proto === 'https';
}

function setCookie(r, value, maxAge) {
    r.headersOut['Set-Cookie'] = COOKIE + '=' + value + '; Path=/; Max-Age=' + maxAge +
        '; HttpOnly; SameSite=Lax' + (isHttps(r) ? '; Secure' : '');
}

// Only allow same-site relative paths, never back into /_gate/.
function safeNext(v) {
    if (typeof v !== 'string' || v.length === 0 || v.length > 2048) return '/';
    if (v[0] !== '/' || v[1] === '/' || v[1] === '\\') return '/';
    if (/[\x00-\x1f\x7f]/.test(v)) return '/';
    if (v.indexOf('/_gate/') === 0) return '/';
    return v;
}

function firstValue(v) {
    if (Array.isArray(v)) return v.length ? String(v[0]) : '';
    return typeof v === 'string' ? v : '';
}

function escapeHtml(s) {
    return String(s)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#39;');
}

// ---------- page rendering ----------

function renderPage(r, status, opts) {
    const accent = /^#[0-9a-fA-F]{3,8}$/.test(env('LOGIN_ACCENT', '')) ? env('LOGIN_ACCENT', '') : DEFAULT_ACCENT;
    let message = '';
    if (opts.error) {
        message = '<div class="msg msg-error" role="alert">' + escapeHtml(opts.error) + '</div>';
    } else if (opts.notice) {
        message = '<div class="msg msg-notice" role="status">' + escapeHtml(opts.notice) + '</div>';
    }
    const values = {
        TITLE: escapeHtml(env('LOGIN_TITLE', 'Private service')),
        SUBTITLE: escapeHtml(env('LOGIN_SUBTITLE', 'Sign in to continue')),
        ACCENT: accent,
        MESSAGE: message,
        USERNAME: escapeHtml(opts.username || ''),
        NEXT: escapeHtml(opts.next || '/'),
        USER_AUTOFOCUS: opts.username ? '' : 'autofocus',
        PASS_AUTOFOCUS: opts.username ? 'autofocus' : '',
    };
    let html = fs.readFileSync(TEMPLATE_FILE, 'utf8');
    Object.keys(values).forEach(function (k) {
        html = html.split('{{' + k + '}}').join(values[k]);
    });

    r.headersOut['Content-Type'] = 'text/html; charset=utf-8';
    r.headersOut['Cache-Control'] = 'no-store';
    r.headersOut['X-Frame-Options'] = 'DENY';
    r.headersOut['X-Content-Type-Options'] = 'nosniff';
    r.headersOut['Referrer-Policy'] = 'no-referrer';
    r.headersOut['Content-Security-Policy'] =
        "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'";
    r.return(status, html);
}

// ---------- handlers ----------

// js_set $gate_user gate.user;
function user(r) {
    return sessionUser(r) || basicUser(r);
}

// js_set $gate_upstream_authorization gate.upstreamAuthorization;
// Drop the Authorization header when it carried *gate* credentials, so the
// upstream never sees the password. Any other value (e.g. a Bearer token
// for the app's own API) passes through unchanged.
function upstreamAuthorization(r) {
    const h = r.headersIn.Authorization || '';
    return basicUser(r) ? '' : h;
}

// error_page 401 = @gate_unauthorized;
function unauthorized(r) {
    const accept = r.headersIn.Accept || '';
    const wantsHtml = accept.indexOf('text/html') !== -1;
    if ((r.method === 'GET' || r.method === 'HEAD') && wantsHtml) {
        const next = safeNext(r.variables.request_uri);
        const target = next === '/' ? '/_gate/login' : '/_gate/login?next=' + encodeURIComponent(next);
        r.headersOut['Cache-Control'] = 'no-store';
        r.return(302, target);
        return;
    }
    r.headersOut['Content-Type'] = 'application/json';
    r.headersOut['Cache-Control'] = 'no-store';
    r.return(401, '{"error":"unauthorized"}\n');
}

// location = /_gate/login
function login(r) {
    if (r.method === 'POST') {
        const form = qs.parse(r.requestText || '');
        const username = firstValue(form.username).trim();
        const password = firstValue(form.password);
        const next = safeNext(firstValue(form.next));
        if (username && password && checkPassword(username, password)) {
            setCookie(r, issueToken(username), sessionSeconds());
            r.headersOut['Cache-Control'] = 'no-store';
            r.return(303, next);
            return;
        }
        r.warn('gate: failed login for "' + username + '" from ' + r.remoteAddress);
        renderPage(r, 401, { error: 'Incorrect username or password.', username: username, next: next });
        return;
    }
    if (r.method !== 'GET' && r.method !== 'HEAD') {
        r.headersOut['Allow'] = 'GET, HEAD, POST';
        r.return(405);
        return;
    }
    const next = safeNext(r.args.next);
    if (sessionUser(r)) {
        r.return(302, next);
        return;
    }
    renderPage(r, 200, {
        next: next,
        notice: r.args.signed_out === '1' ? 'You have been signed out.' : '',
    });
}

// error_page 429 = @gate_rate_limited;
function rateLimited(r) {
    renderPage(r, 429, { error: 'Too many sign-in attempts. Wait a minute and try again.', next: '/' });
}

// location = /_gate/logout
function logout(r) {
    setCookie(r, '', 0);
    r.headersOut['Cache-Control'] = 'no-store';
    r.return(302, '/_gate/login?signed_out=1');
}

export default { user, upstreamAuthorization, unauthorized, login, logout, rateLimited };
