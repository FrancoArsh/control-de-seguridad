FROM node:20-alpine AS build

WORKDIR /app
COPY backend/package*.json ./backend/
RUN cd backend && npm ci
COPY backend/tsconfig.json ./backend/
COPY backend/src ./backend/src
RUN cd backend && npm run build

FROM node:20-alpine
ENV NODE_ENV=production
WORKDIR /app
COPY backend/package*.json ./backend/
RUN cd backend && npm ci --omit=dev
COPY --from=build /app/backend/dist ./backend/dist
COPY frontend ./frontend

EXPOSE 3000
CMD ["node", "backend/dist/server.js"]
