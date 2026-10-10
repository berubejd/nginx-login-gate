FROM nginx:1.28-alpine

# bash for the entrypoint, envsubst (gettext) for templating.
# The official nginx image already ships the njs module.
RUN apk add --no-cache bash gettext

RUN mkdir -p /etc/nginx/snippets /etc/nginx/gate

COPY nginx.conf /etc/nginx/nginx.conf
# Template lives outside /etc/nginx/templates so the stock envsubst step skips it
COPY nginx.conf.template /etc/nginx/gate/gate.conf.template
COPY gate.js login.html /etc/nginx/gate/

# Runs after the stock nginx entrypoint setup
COPY docker-entrypoint.sh /docker-entrypoint.d/99-gate.sh
RUN chmod +x /docker-entrypoint.d/99-gate.sh

EXPOSE 80

ENV ORIGIN="" \
    AUTH_USERS="" \
    SESSION_HOURS="168" \
    ALLOW_BASIC_AUTH="true" \
    TRUST_PROXY_HEADERS="true" \
    LOGIN_TITLE="Private service" \
    LOGIN_SUBTITLE="Sign in to continue"

CMD ["nginx", "-g", "daemon off;"]
