#!/usr/bin/env bash
# Runs from /docker-entrypoint.d/ before nginx starts (official nginx image).
# Validates settings, writes the session secret and auth snippet, and renders
# the nginx config. Based on biw/railway-nginx-password-auth.
set -euo pipefail

log() { echo "[gate] $*"; }
die() { echo "[gate] ERROR: $*" >&2; exit 1; }

GATE_DIR="/etc/nginx/gate"
SNIPPET="/etc/nginx/snippets/gate_check.conf"
SECRET_FILE="$GATE_DIR/secret"
TEMPLATE="$GATE_DIR/gate.conf.template"
OUTPUT="/etc/nginx/conf.d/gate.conf"

# ---------- ORIGIN ----------
[[ -n "${ORIGIN:-}" ]] || die "ORIGIN env var is required (e.g. http://app.railway.internal:3000)"
[[ "$ORIGIN" == http://* || "$ORIGIN" == https://* ]] || die "ORIGIN must start with http:// or https://"

# ---------- Users ----------
# AUTH_USERS="alice:pw1,bob:pw2". BASIC_AUTH is accepted as an alias.
USERS_RAW="${AUTH_USERS:-${BASIC_AUTH:-}}"

if [[ -z "$USERS_RAW" ]]; then
  if [[ "${ALLOW_NO_AUTH:-}" == "true" ]]; then
    log "No users configured - auth DISABLED (ALLOW_NO_AUTH=true)"
    : > "$SNIPPET"
  else
    die "AUTH_USERS is required, e.g. AUTH_USERS=alice:pw1,bob:pw2 (or set ALLOW_NO_AUTH=true)"
  fi
else
  declare -A SEEN=()
  NAMES=()
  IFS=',' read -ra PAIRS <<< "$USERS_RAW"
  for pair in "${PAIRS[@]}"; do
    # Allow "alice:pw1, bob:pw2"
    pair="${pair#"${pair%%[![:space:]]*}"}"
    pair="${pair%"${pair##*[![:space:]]}"}"
    [[ -z "$pair" ]] && continue
    [[ "$pair" == *:* ]] || die "Each user must be 'username:password' (got an entry without a colon)"
    name="${pair%%:*}"
    pass="${pair#*:}"
    [[ -n "$name" && -n "$pass" ]] || die "Empty username or password in AUTH_USERS"
    [[ "$name" =~ ^[A-Za-z0-9._@+-]+$ ]] || die "Username '$name' has invalid characters (allowed: letters, digits, . _ @ + -)"
    [[ -z "${SEEN[$name]:-}" ]] || die "Username '$name' appears more than once in AUTH_USERS"
    SEEN[$name]=1
    NAMES+=("$name")
  done
  (( ${#NAMES[@]} > 0 )) || die "AUTH_USERS did not contain any users"

  cat > "$SNIPPET" <<'EOF'
if ($gate_user = "") {
    return 401;
}
EOF
  log "Login enabled for ${#NAMES[@]} user(s): ${NAMES[*]}"
fi

# ---------- Session settings ----------
if [[ -n "${SESSION_HOURS:-}" && ! "$SESSION_HOURS" =~ ^[1-9][0-9]*$ ]]; then
  die "SESSION_HOURS must be a positive whole number (got '$SESSION_HOURS')"
fi
log "Sessions last ${SESSION_HOURS:-168} hours"

if [[ "${ALLOW_BASIC_AUTH:-true}" == "true" ]]; then
  log "Basic auth header also accepted (for scripts/CLI). Set ALLOW_BASIC_AUTH=false to disable."
fi

if [[ -n "${LOGIN_ACCENT:-}" && ! "$LOGIN_ACCENT" =~ ^#[0-9a-fA-F]{3,8}$ ]]; then
  log "WARNING: LOGIN_ACCENT '$LOGIN_ACCENT' is not a hex color like #4f46e5 - using the default"
fi

mkdir -p "$GATE_DIR"
if [[ -n "${SESSION_SECRET:-}" ]]; then
  (( ${#SESSION_SECRET} >= 32 )) || log "WARNING: SESSION_SECRET is short; use 32+ random characters"
  printf '%s' "$SESSION_SECRET" > "$SECRET_FILE"
else
  head -c 48 /dev/urandom | base64 | tr -d '\n' > "$SECRET_FILE"
  log "WARNING: SESSION_SECRET not set - using a random one. Everyone will be signed out on every restart/redeploy."
fi
chmod 0640 "$SECRET_FILE"
chgrp nginx "$SECRET_FILE" 2>/dev/null || chmod 0644 "$SECRET_FILE"

# ---------- Real client IP ----------
# Behind Railway (or any proxy), the TCP peer is the proxy, not the visitor.
# With TRUST_PROXY_HEADERS=true, nginx takes the client IP from the LAST
# X-Forwarded-For entry (the one the proxy added), so $remote_addr, logs,
# X-Real-IP and the login rate limiter all use the visitor's IP. The scheme
# forwarded upstream is the last X-Forwarded-Proto entry, for the same reason.
# Only enable this when the gate can be reached solely through a proxy.
REALIP_SNIPPET="/etc/nginx/snippets/gate_realip.conf"
if [[ "${TRUST_PROXY_HEADERS:-true}" == "true" ]]; then
  cat > "$REALIP_SNIPPET" <<'EOF'
real_ip_header X-Forwarded-For;
real_ip_recursive off;
set_real_ip_from 0.0.0.0/0;
set_real_ip_from ::/0;
EOF
  # Forward the proxy's chain plus the proxy hop itself (not the client twice).
  # Report the proxy's scheme too, so the app sees https behind a TLS-terminating edge.
  GATE_XFF='$gate_xff_trusted'
  GATE_XFP='$gate_xfp_trusted'
  log "Trusting proxy headers for the client IP and scheme (TRUST_PROXY_HEADERS=true)"
else
  : > "$REALIP_SNIPPET"
  GATE_XFF='$proxy_add_x_forwarded_for'
  GATE_XFP='$scheme'
  log "Not trusting proxy headers - client IP is the direct TCP peer, scheme is the gate connection"
fi

# ---------- DNS resolver ----------
# nginx queries the resolver list round-robin, one server per lookup, and
# treats NXDOMAIN as a final answer. It does not fall through to the next
# server. Public resolvers cannot answer private names (*.railway.internal,
# Docker service names), so they must not be mixed in with the container's
# own nameserver. /etc/resolv.conf "search" domains are also ignored; ORIGIN
# has to be a name that nameserver can answer as written.
DNS_RESOLVER=""
if [[ -f /etc/resolv.conf ]]; then
  FORMATTED_NAMESERVERS=""
  while IFS= read -r nameserver; do
    if [[ -n "$nameserver" ]]; then
      if [[ "$nameserver" == *":"* ]]; then
        FORMATTED_NAMESERVERS="$FORMATTED_NAMESERVERS [$nameserver]"  # IPv6 needs brackets
      else
        FORMATTED_NAMESERVERS="$FORMATTED_NAMESERVERS $nameserver"
      fi
    fi
  done <<< "$(grep '^nameserver' /etc/resolv.conf | awk '{print $2}')"
  DNS_RESOLVER="${FORMATTED_NAMESERVERS# }"
fi

if [[ -n "$DNS_RESOLVER" ]]; then
  log "Using system DNS resolvers: $DNS_RESOLVER"
else
  DNS_RESOLVER="8.8.8.8 8.8.4.4"
  log "WARNING: no nameserver in /etc/resolv.conf, using public DNS. Private hostnames such as *.railway.internal will not resolve."
fi

# ---------- Render nginx config ----------
[[ -f "$TEMPLATE" ]] || die "missing $TEMPLATE"
export DNS_RESOLVER GATE_XFF GATE_XFP
envsubst '\$ORIGIN \$DNS_RESOLVER \$GATE_XFF \$GATE_XFP' < "$TEMPLATE" > "$OUTPUT"
[[ -s "$OUTPUT" ]] || die "Failed to generate nginx configuration"

# Remove the stock config to avoid conflicts
rm -f /etc/nginx/conf.d/default.conf

log "Testing nginx configuration..."
nginx -t || die "Invalid nginx configuration"
log "Proxying to ORIGIN=$ORIGIN"
