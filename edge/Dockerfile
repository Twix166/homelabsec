FROM nginx:1.27-alpine

RUN apk add --no-cache apache2-utils gettext openssl

COPY nginx.conf.template /etc/nginx/templates/default.conf.template
COPY nginx.oauth2_proxy.conf.template /etc/nginx/templates/oauth2_proxy.conf.template
COPY docker-entrypoint.sh /docker-entrypoint.sh

RUN chmod +x /docker-entrypoint.sh

ENTRYPOINT ["/docker-entrypoint.sh"]
