FROM prom/alertmanager:v0.28.1

USER root
COPY docker-entrypoint.sh /docker-entrypoint.sh
RUN chmod +x /docker-entrypoint.sh
USER nobody

ENTRYPOINT ["/docker-entrypoint.sh"]
