# Playwright official image — Node 20 + Chromium + system deps preinstalled
# Version MUST match the playwright npm package version (see package.json).
FROM mcr.microsoft.com/playwright:v1.59.1-jammy

WORKDIR /app

COPY package.json package-lock.json* ./
RUN npm install --omit=dev

COPY tsconfig.json ./
COPY src ./src

ENV NODE_ENV=production
ENV PORT=3030
ENV X_STATE_PATH=/data/x-state.json

EXPOSE 3030

# dumb-init reaps zombie Chromium processes if Node crashes mid-flight
CMD ["dumb-init", "npm", "start"]
