# syntax=docker/dockerfile:1

# Versión de Go configurable. La guía usa 1.22; puedes reconstruir con una versión
# soportada (por ejemplo --build-arg GO_VERSION=1.27) para remediar CVE de la stdlib.
ARG GO_VERSION=1.22

# ---------- Etapa 1: compilación ----------
FROM golang:${GO_VERSION} AS build
ARG VERSION=1.0.0
WORKDIR /src

# Primero solo los manifiestos para aprovechar la caché de capas
COPY go.mod go.sum* ./
RUN go mod download

COPY . .
# El código vive en ./app (corrección respecto a la guía, que compilaba "." en la raíz)
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath \
    -ldflags="-s -w -X main.version=${VERSION}" \
    -o /out/app ./app

# ---------- Etapa 2: imagen final mínima ----------
# distroless/static: sin shell ni gestor de paquetes; usuario no root (UID 65532)
FROM gcr.io/distroless/static-debian12:nonroot
WORKDIR /
COPY --from=build /out/app /app
USER nonroot:nonroot
EXPOSE 8080
ENTRYPOINT ["/app"]
