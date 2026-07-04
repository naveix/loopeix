# Pinned to the declared engines floor — this cell doubles as the Node 22.12 proof on Linux.
FROM node:22.12-bookworm-slim

# Pre-baked warm image (verifier condition): the persona starts with loopeix installed,
# so hundreds of rollouts don't each pay a cold npm install.
COPY loopeix-0.0.0.tgz /opt/loopeix.tgz
COPY fixtures /opt/fixtures
RUN npm install -g /opt/loopeix.tgz && loopeix --version

WORKDIR /app
