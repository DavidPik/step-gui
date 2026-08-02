FROM node:20-alpine AS frontend
WORKDIR /app
COPY frontend/ .
RUN npm install && npm run build

FROM golang:1.22-alpine AS backend
WORKDIR /app
COPY . .
RUN go build -o gui-backend ./cmd/gui-backend

FROM alpine:3.19
WORKDIR /app
COPY --from=backend /app/gui-backend /app/gui-backend
COPY --from=frontend /app/build /app/frontend
COPY config/ /app/config/
ENTRYPOINT ["/app/gui-backend"]
