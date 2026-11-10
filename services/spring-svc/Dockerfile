FROM eclipse-temurin:17-jdk-alpine AS build

WORKDIR /src
COPY SpringSvc.java .
RUN javac -encoding UTF-8 -d /src/classes SpringSvc.java

FROM eclipse-temurin:17-jre-alpine

WORKDIR /app
COPY --from=build /src/classes ./classes
COPY documents/ ./documents/

ENV PORT=8080
ENV DOCUMENTS_DIR=/app/documents
EXPOSE 8080

HEALTHCHECK --interval=10s --timeout=5s --start-period=15s --retries=5 \
  CMD wget -qO- http://127.0.0.1:8080/health || exit 1

CMD ["java", "-cp", "/app/classes", "SpringSvc"]
