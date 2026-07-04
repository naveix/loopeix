# No credentials in this cell by design — adversarial personas never see live auth.
FROM node:22.12-bookworm-slim

COPY loopeix-0.0.0.tgz /opt/loopeix.tgz
COPY fixtures /opt/fixtures
RUN npm install -g /opt/loopeix.tgz && loopeix --version && apt-get update && apt-get install -y jq && rm -rf /var/lib/apt/lists/*

WORKDIR /app
