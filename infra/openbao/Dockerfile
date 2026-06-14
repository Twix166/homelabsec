FROM openbao/openbao:latest

USER root
RUN apk add --no-cache curl \
    && mkdir -p /bao/file /bao/logs \
    && chown -R openbao:openbao /bao
