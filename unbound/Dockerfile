# Built from Alpine rather than a third-party Unbound image: this container sits in
# the DNS path for every check, so the fewer opaque layers the better.
FROM alpine:3.21

RUN apk add --no-cache unbound drill \
 && mkdir -p /var/lib/unbound \
 && unbound-anchor -a /var/lib/unbound/root.key || true \
 && chown -R unbound:unbound /var/lib/unbound

COPY unbound.conf /etc/unbound/unbound.conf

EXPOSE 53/udp 53/tcp

# A recursion that resolves a real name proves the container is actually working,
# not merely listening.
HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
  CMD drill -Q @127.0.0.1 example.com A || exit 1

USER unbound
CMD ["unbound", "-d", "-c", "/etc/unbound/unbound.conf"]
