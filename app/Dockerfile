# Astro 7 requires Node >= 22.12.
FROM node:22-alpine AS build
WORKDIR /app

# Install against the lockfile first so dependency layers survive source edits.
COPY package.json package-lock.json ./
RUN npm ci

COPY . .
RUN npm run build && npm prune --omit=dev

FROM node:22-alpine AS runtime
WORKDIR /app
ENV NODE_ENV=production HOST=0.0.0.0 PORT=3000

# The app makes outbound DNS queries and nothing else; it never needs write access
# to its own code.
RUN addgroup -S app && adduser -S app -G app

COPY --from=build --chown=app:app /app/node_modules ./node_modules
COPY --from=build --chown=app:app /app/dist ./dist
COPY --from=build --chown=app:app /app/package.json ./package.json

USER app
EXPOSE 3000

# Probes /healthz, not / — hitting the landing page rendered the full document every
# 30s and, once stats existed, recorded each probe as a page view.
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD node -e "fetch('http://127.0.0.1:3000/healthz').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"

CMD ["node", "./dist/server/entry.mjs"]
