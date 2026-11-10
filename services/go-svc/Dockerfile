FROM golang:1.22-alpine AS build

WORKDIR /src
COPY go.mod ./
COPY main.go ./
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -o /src/go-svc .

FROM alpine:3.20

WORKDIR /app
COPY --from=build /src/go-svc ./go-svc
COPY documents/ ./documents/

ENV PORT=8090
EXPOSE 8090

HEALTHCHECK --interval=10s --timeout=5s --start-period=10s --retries=5 \
  CMD wget -qO- http://127.0.0.1:8090/health || exit 1

CMD ["./go-svc"]
