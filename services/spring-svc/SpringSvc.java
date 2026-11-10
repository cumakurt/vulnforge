// VulnForge Lab — spring-svc
//
// Intentionally vulnerable Java service used for scanner benchmarking.
// Implemented with the JDK HTTP server to keep the build dependency-free and
// reproducible; it exposes the same vulnerability classes the plan assigns to
// the Java tier (XXE, deserialization, expression injection, JNDI lookup
// simulation, path traversal, weak crypto, command injection).
//
// WARNING: never expose this service outside an isolated lab.

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;

import java.beans.XMLDecoder;
import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.StringReader;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.URLDecoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.time.Duration;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;

import org.w3c.dom.Document;
import org.w3c.dom.NodeList;

public final class SpringSvc {

    private static final int PORT = Integer.parseInt(System.getenv().getOrDefault("PORT", "8080"));
    private static final String LAB_CONTROL_URL =
            System.getenv().getOrDefault("LAB_CONTROL_URL", "http://lab-control:9100");
    private static final String OOB_COLLECTOR_URL =
            System.getenv().getOrDefault("OOB_COLLECTOR_URL", "http://oob-collector:9000");
    private static final String DOCUMENTS_DIR =
            System.getenv().getOrDefault("DOCUMENTS_DIR", "/app/documents");

    private static final HttpClient HTTP = HttpClient.newBuilder()
            .connectTimeout(Duration.ofSeconds(2))
            .build();

    // Simulated "gadget" class reachable through the unsafe deserializer.
    // A real deployment would ship a vulnerable library on the classpath; the
    // lab exposes an equivalent primitive so the class stays reproducible.
    private static volatile String PWNED = "no";

    public static class Gadget {
        public Gadget() {
        }

        public void setCommand(String command) {
            try {
                new ProcessBuilder("sh", "-c", command).redirectErrorStream(true).start().waitFor();
            } catch (Exception ignored) {
                // The side effect of reaching this setter is the finding.
            }
            PWNED = "yes";
        }
    }

    public static void main(String[] args) throws IOException {
        HttpServer server = HttpServer.create(new InetSocketAddress("0.0.0.0", PORT), 0);

        server.createContext("/health", exchange -> json(exchange, 200, "{\"status\":\"ok\",\"service\":\"spring-svc\"}"));
        server.createContext("/actuator/health", exchange -> json(exchange, 200, "{\"status\":\"UP\"}"));
        server.createContext("/__lab/internal/reset", exchange -> json(exchange, 200, "{\"reset\":true}"));

        server.createContext("/java/xxe", SpringSvc::xxeHandler);
        server.createContext("/java/xxe_safe", SpringSvc::xxeSafeHandler);
        server.createContext("/java/deserialize", SpringSvc::deserializeHandler);
        server.createContext("/java/deserialize_safe", SpringSvc::deserializeSafeHandler);
        server.createContext("/java/template", SpringSvc::templateHandler);
        server.createContext("/java/template_safe", SpringSvc::templateSafeHandler);
        server.createContext("/java/log", SpringSvc::logHandler);
        server.createContext("/java/log_safe", SpringSvc::logSafeHandler);
        server.createContext("/java/download", SpringSvc::downloadHandler);
        server.createContext("/java/download_safe", SpringSvc::downloadSafeHandler);
        server.createContext("/java/actuator/env", SpringSvc::actuatorEnvHandler);
        server.createContext("/java/actuator/env_safe", SpringSvc::actuatorEnvSafeHandler);
        server.createContext("/java/encrypt", SpringSvc::encryptHandler);
        server.createContext("/java/encrypt_safe", SpringSvc::encryptSafeHandler);
        server.createContext("/java/exec", SpringSvc::execHandler);
        server.createContext("/java/exec_safe", SpringSvc::execSafeHandler);
        server.createContext("/java/go", SpringSvc::redirectHandler);
        server.createContext("/java/go_safe", SpringSvc::redirectSafeHandler);
        server.createContext("/java/stack", SpringSvc::stackHandler);
        server.createContext("/java/stack_safe", SpringSvc::stackSafeHandler);

        server.setExecutor(java.util.concurrent.Executors.newFixedThreadPool(8));
        server.start();
        System.out.println("[spring-svc] listening on " + PORT);
    }

    // ─── HTTP helpers ────────────────────────────────────────────────────────

    private static void json(HttpExchange exchange, int status, String body) throws IOException {
        byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().set("Content-Type", "application/json; charset=utf-8");
        exchange.sendResponseHeaders(status, bytes.length);
        try (OutputStream out = exchange.getResponseBody()) {
            out.write(bytes);
        }
    }

    private static void text(HttpExchange exchange, int status, String body) throws IOException {
        byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().set("Content-Type", "text/plain; charset=utf-8");
        exchange.sendResponseHeaders(status, bytes.length);
        try (OutputStream out = exchange.getResponseBody()) {
            out.write(bytes);
        }
    }

    private static String body(HttpExchange exchange) throws IOException {
        return new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
    }

    private static Map<String, String> query(HttpExchange exchange) {
        Map<String, String> params = new HashMap<>();
        String raw = exchange.getRequestURI().getRawQuery();
        if (raw == null || raw.isEmpty()) {
            return params;
        }
        for (String pair : raw.split("&")) {
            int idx = pair.indexOf('=');
            String key = idx >= 0 ? pair.substring(0, idx) : pair;
            String value = idx >= 0 ? pair.substring(idx + 1) : "";
            params.put(URLDecoder.decode(key, StandardCharsets.UTF_8), URLDecoder.decode(value, StandardCharsets.UTF_8));
        }
        return params;
    }

    private static String escape(String value) {
        return value.replace("\\", "\\\\").replace("\"", "\\\"").replace("\n", "\\n");
    }

    private static void labTrigger(String vulnId, HttpExchange exchange, Map<String, String> extra) {
        StringBuilder builder = new StringBuilder();
        builder.append("{\"kind\":\"vuln_triggered\",")
                .append("\"vuln_id\":\"").append(vulnId).append("\",")
                .append("\"service\":\"spring-svc\",")
                .append("\"request_id\":\"").append(escape(exchange.getRequestHeaders().getFirst("X-Request-Id") == null
                        ? "" : exchange.getRequestHeaders().getFirst("X-Request-Id"))).append("\",")
                .append("\"ts\":\"").append(java.time.Instant.now()).append("\"");

        for (Map.Entry<String, String> entry : extra.entrySet()) {
            builder.append(",\"").append(escape(entry.getKey())).append("\":\"")
                    .append(escape(entry.getValue())).append("\"");
        }
        builder.append("}");

        HttpRequest request = HttpRequest.newBuilder(URI.create(LAB_CONTROL_URL + "/__lab/events"))
                .timeout(Duration.ofSeconds(1))
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(builder.toString()))
                .build();
        HTTP.sendAsync(request, HttpResponse.BodyHandlers.discarding());
    }

    // ─── XXE ────────────────────────────────────────────────────────────────

    // @vuln id=JAVA-001 name="XXE in XML import endpoint" cwe=CWE-611 owasp=A05:2021 type=xxe level=1 param=body method=POST service=spring-svc url=/java/xxe param_loc=body needs_oob=false auth=false detection=active tags=xxe,xml,injection proof_kind=marker proof_desc="External entity is resolved and file contents appear in the response"
    private static void xxeHandler(HttpExchange exchange) throws IOException {
        String xml = body(exchange);
        try {
            // !! INTENTIONALLY VULNERABLE — external entities left enabled !!
            DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
            DocumentBuilder builder = factory.newDocumentBuilder();
            Document document = builder.parse(new ByteArrayInputStream(xml.getBytes(StandardCharsets.UTF_8)));
            NodeList nodes = document.getElementsByTagName("name");

            String value = nodes.getLength() > 0 ? nodes.item(0).getTextContent() : "";
            if (xml.contains("<!ENTITY")) {
                labTrigger("JAVA-001", exchange, Map.of("payload", xml.substring(0, Math.min(xml.length(), 200))));
            }
            text(exchange, 200, "parsed name: " + value);
        } catch (Exception error) {
            text(exchange, 500, "parse error: " + error);
        }
    }

    // @control id=JAVA-001-C twin_of=JAVA-001 url=/java/xxe_safe method=POST param=body service=spring-svc param_loc=body
    private static void xxeSafeHandler(HttpExchange exchange) throws IOException {
        String xml = body(exchange);
        try {
            DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
            // SAFE: DOCTYPE declarations and external entities are disabled.
            factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
            factory.setFeature("http://xml.org/sax/features/external-general-entities", false);
            factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
            factory.setXIncludeAware(false);
            factory.setExpandEntityReferences(false);

            DocumentBuilder builder = factory.newDocumentBuilder();
            Document document = builder.parse(new ByteArrayInputStream(xml.getBytes(StandardCharsets.UTF_8)));
            NodeList nodes = document.getElementsByTagName("name");
            text(exchange, 200, "parsed name: " + (nodes.getLength() > 0 ? nodes.item(0).getTextContent() : ""));
        } catch (Exception error) {
            text(exchange, 400, "invalid xml");
        }
    }

    // ─── Deserialization ────────────────────────────────────────────────────

    // @vuln id=JAVA-002 name="XMLDecoder deserialization enables method invocation" cwe=CWE-502 owasp=A08:2021 type=insecure-deserialization level=1 param=data method=POST service=spring-svc url=/java/deserialize param_loc=body needs_oob=false auth=false detection=active tags=deserialization,xml,rce proof_kind=marker proof_desc="XMLDecoder executes a method call supplied by the client"
    private static void deserializeHandler(HttpExchange exchange) throws IOException {
        String raw = body(exchange);
        try {
            // !! INTENTIONALLY VULNERABLE — XMLDecoder executes arbitrary methods !!
            XMLDecoder decoder = new XMLDecoder(new ByteArrayInputStream(raw.getBytes(StandardCharsets.UTF_8)));
            decoder.readObject();
            decoder.close();

            String marker = PWNED;
            labTrigger("JAVA-002", exchange, Map.of("pwned", marker));
            json(exchange, 200, "{\"deserialized\":true,\"pwned\":\"" + escape(marker) + "\"}");
        } catch (Exception error) {
            text(exchange, 500, "deserialization error: " + error);
        }
    }

    // @control id=JAVA-002-C twin_of=JAVA-002 url=/java/deserialize_safe method=POST param=data service=spring-svc param_loc=body
    private static void deserializeSafeHandler(HttpExchange exchange) throws IOException {
        String raw = body(exchange);
        // SAFE: only allow-listed JSON keys are accepted; no object construction.
        if (!raw.startsWith("{") || raw.contains("java.") || raw.contains("<")) {
            text(exchange, 400, "unsupported payload");
            return;
        }
        json(exchange, 200, "{\"deserialized\":true}");
    }

    // ─── Expression injection ──────────────────────────────────────────────

    // @vuln id=JAVA-003 name="Expression language injection in template renderer" cwe=CWE-917 owasp=A03:2021 type=el-injection level=2 param=name method=GET service=spring-svc url=/java/template param_loc=query needs_oob=false auth=false detection=active tags=injection,el,ssti proof_kind=marker proof_desc="The file: expression resolver reads arbitrary files"
    private static void templateHandler(HttpExchange exchange) throws IOException {
        String name = query(exchange).getOrDefault("name", "World");
        String rendered = renderTemplate(name, true);
        if (name.contains("${")) {
            labTrigger("JAVA-003", exchange, Map.of("payload", name));
        }
        text(exchange, 200, "Hello " + rendered);
    }

    // @control id=JAVA-003-C twin_of=JAVA-003 url=/java/template_safe method=GET param=name service=spring-svc param_loc=query
    private static void templateSafeHandler(HttpExchange exchange) throws IOException {
        String name = query(exchange).getOrDefault("name", "World");
        text(exchange, 200, "Hello " + renderTemplate(name, false));
    }

    private static String renderTemplate(String input, boolean unsafe) {
        StringBuilder output = new StringBuilder();
        int index = 0;
        while (index < input.length()) {
            int start = input.indexOf("${", index);
            if (start < 0) {
                output.append(input.substring(index));
                break;
            }
            output.append(input, index, start);
            int end = input.indexOf('}', start);
            if (end < 0) {
                output.append(input.substring(start));
                break;
            }
            String expression = input.substring(start + 2, end);
            output.append(resolveExpression(expression, unsafe));
            index = end + 1;
        }
        return output.toString();
    }

    private static String resolveExpression(String expression, boolean unsafe) {
        if (expression.equals("name")) {
            return "";
        }
        if (!unsafe) {
            return "${" + expression + "}";
        }
        if (expression.startsWith("env:")) {
            return String.valueOf(System.getenv(expression.substring(4)));
        }
        if (expression.startsWith("sys:")) {
            return String.valueOf(System.getProperty(expression.substring(4)));
        }
        if (expression.startsWith("file:")) {
            // !! INTENTIONALLY VULNERABLE — arbitrary file read via EL !!
            try {
                return Files.readString(Paths.get(expression.substring(5)));
            } catch (IOException error) {
                return "file-error";
            }
        }
        return "${" + expression + "}";
    }

    // ─── JNDI lookup simulation ────────────────────────────────────────────

    // @vuln id=JAVA-004 name="Log4Shell-style JNDI lookup performed on log input" cwe=CWE-917 owasp=A03:2021 type=jndi-lookup level=2 param=msg method=GET service=spring-svc url=/java/log param_loc=query needs_oob=true auth=false detection=active tags=injection,jndi,oob proof_kind=oob proof_desc="A ${jndi:...} payload triggers an out-of-band lookup callback"
    private static void logHandler(HttpExchange exchange) throws IOException {
        String message = query(exchange).getOrDefault("msg", "hello");
        boolean looked = false;

        int start = message.indexOf("${jndi:");
        if (start >= 0) {
            int end = message.indexOf('}', start);
            String lookup = end > start ? message.substring(start + 7, end) : "";
            // !! INTENTIONALLY VULNERABLE — lookup target is attacker controlled !!
            try {
                String token = lookup.replaceAll("[^A-Za-z0-9_-]", "_");
                HTTP.send(HttpRequest.newBuilder(URI.create(OOB_COLLECTOR_URL + "/oob/" + token))
                        .timeout(Duration.ofSeconds(2)).GET().build(),
                        HttpResponse.BodyHandlers.discarding());
                looked = true;
            } catch (Exception ignored) {
                looked = true; // the attempt itself is the finding
            }
            labTrigger("JAVA-004", exchange, Map.of("payload", message));
        }

        json(exchange, 200, "{\"logged\":true,\"lookup_performed\":" + looked + "}");
    }

    // @control id=JAVA-004-C twin_of=JAVA-004 url=/java/log_safe method=GET param=msg service=spring-svc param_loc=query
    private static void logSafeHandler(HttpExchange exchange) throws IOException {
        // SAFE: lookup syntax is neutralised before logging.
        String message = query(exchange).getOrDefault("msg", "hello").replace("${", "\\${");
        json(exchange, 200, "{\"logged\":true,\"message\":\"" + escape(message) + "\"}");
    }

    // ─── Path traversal ────────────────────────────────────────────────────

    // @vuln id=JAVA-005 name="Path traversal in document download" cwe=CWE-22 owasp=A01:2021 type=path-traversal level=1 param=file method=GET service=spring-svc url=/java/download param_loc=query needs_oob=false auth=false detection=active tags=file,traversal proof_kind=marker proof_desc="Arbitrary files can be read through the file parameter"
    private static void downloadHandler(HttpExchange exchange) throws IOException {
        String name = query(exchange).getOrDefault("file", "readme.txt");
        // !! INTENTIONALLY VULNERABLE — no canonicalisation check !!
        Path path = Paths.get(DOCUMENTS_DIR, name);
        try {
            String content = Files.readString(path);
            if (name.contains("..")) {
                labTrigger("JAVA-005", exchange, Map.of("payload", name));
            }
            text(exchange, 200, content);
        } catch (IOException error) {
            text(exchange, 404, "file not found");
        }
    }

    // @control id=JAVA-005-C twin_of=JAVA-005 url=/java/download_safe method=GET param=file service=spring-svc param_loc=query
    private static void downloadSafeHandler(HttpExchange exchange) throws IOException {
        String name = query(exchange).getOrDefault("file", "readme.txt");
        if (!name.equals("readme.txt") && !name.equals("about.txt")) {
            text(exchange, 400, "invalid file");
            return;
        }
        Path base = Paths.get(DOCUMENTS_DIR).toAbsolutePath().normalize();
        Path path = base.resolve(name).normalize();
        if (!path.startsWith(base)) {
            text(exchange, 400, "invalid file");
            return;
        }
        text(exchange, 200, Files.readString(path));
    }

    // ─── Actuator ──────────────────────────────────────────────────────────

    // @vuln id=JAVA-006 name="Actuator environment endpoint exposes secrets" cwe=CWE-200 owasp=A05:2021 type=actuator-exposure level=1 param=none method=GET service=spring-svc url=/java/actuator/env param_loc=path needs_oob=false auth=false detection=config tags=misconfiguration,info-leak,actuator proof_kind=marker proof_desc="Environment variables and application properties are returned without authentication"
    private static void actuatorEnvHandler(HttpExchange exchange) throws IOException {
        StringBuilder builder = new StringBuilder("{\"activeProfiles\":[\"production\"],\"propertySources\":[{\"name\":\"systemEnvironment\",\"properties\":{");
        boolean first = true;
        for (Map.Entry<String, String> entry : System.getenv().entrySet()) {
            if (!first) builder.append(',');
            builder.append('"').append(escape(entry.getKey())).append("\":{\"value\":\"")
                    .append(escape(entry.getValue())).append("\"}");
            first = false;
        }
        builder.append("}}]}");

        labTrigger("JAVA-006", exchange, Map.of());
        json(exchange, 200, builder.toString());
    }

    // @control id=JAVA-006-C twin_of=JAVA-006 url=/java/actuator/env_safe method=GET param=none service=spring-svc param_loc=path
    private static void actuatorEnvSafeHandler(HttpExchange exchange) throws IOException {
        json(exchange, 404, "{\"error\":\"not found\"}");
    }

    // ─── Weak crypto ───────────────────────────────────────────────────────

    // @vuln id=JAVA-007 name="DES/ECB encryption with a hard-coded key" cwe=CWE-327 owasp=A02:2021 type=weak-crypto level=1 param=data method=POST service=spring-svc url=/java/encrypt param_loc=body needs_oob=false auth=false detection=config tags=crypto,weak-cipher proof_kind=marker proof_desc="Response reports DES/ECB with a static key"
    private static void encryptHandler(HttpExchange exchange) throws IOException {
        String data = body(exchange);
        try {
            // !! INTENTIONALLY VULNERABLE — DES, ECB mode, static key !!
            byte[] key = "VULNFORG".getBytes(StandardCharsets.UTF_8);
            Cipher cipher = Cipher.getInstance("DES/ECB/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "DES"));
            String encoded = Base64.getEncoder().encodeToString(cipher.doFinal(data.getBytes(StandardCharsets.UTF_8)));

            labTrigger("JAVA-007", exchange, Map.of("algorithm", "DES/ECB"));
            json(exchange, 200, "{\"algorithm\":\"DES/ECB/PKCS5Padding\",\"key\":\"VULNFORGE\",\"ciphertext\":\"" + encoded + "\"}");
        } catch (Exception error) {
            text(exchange, 500, "encryption error");
        }
    }

    // @control id=JAVA-007-C twin_of=JAVA-007 url=/java/encrypt_safe method=POST param=data service=spring-svc param_loc=body
    private static void encryptSafeHandler(HttpExchange exchange) throws IOException {
        String data = body(exchange);
        try {
            // SAFE: AES/GCM with a random key generated per process start.
            byte[] key = new byte[32];
            new java.security.SecureRandom().nextBytes(key);
            byte[] iv = new byte[12];
            new java.security.SecureRandom().nextBytes(iv);
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"),
                    new javax.crypto.spec.GCMParameterSpec(128, iv));
            String encoded = Base64.getEncoder().encodeToString(cipher.doFinal(data.getBytes(StandardCharsets.UTF_8)));
            json(exchange, 200, "{\"algorithm\":\"AES/GCM/NoPadding\",\"ciphertext\":\"" + encoded + "\"}");
        } catch (Exception error) {
            text(exchange, 500, "encryption error");
        }
    }

    // ─── Command injection ─────────────────────────────────────────────────

    // @vuln id=JAVA-008 name="Command injection in maintenance runner" cwe=CWE-78 owasp=A03:2021 type=os-command level=1 param=cmd method=GET service=spring-svc url=/java/exec param_loc=query needs_oob=false auth=false detection=active tags=injection,command,rce proof_kind=marker proof_desc="Shell metacharacters execute and their output is returned"
    private static void execHandler(HttpExchange exchange) throws IOException {
        String command = query(exchange).getOrDefault("cmd", "hostname");
        try {
            // !! INTENTIONALLY VULNERABLE — sh -c with concatenated input !!
            Process process = new ProcessBuilder("sh", "-c", "echo " + command).redirectErrorStream(true).start();
            String output = readAll(process.getInputStream());
            if (command.matches(".*[;&|`$()].*")) {
                labTrigger("JAVA-008", exchange, Map.of("payload", command));
            }
            text(exchange, 200, output);
        } catch (IOException error) {
            text(exchange, 500, "execution failed");
        }
    }

    // @control id=JAVA-008-C twin_of=JAVA-008 url=/java/exec_safe method=GET param=cmd service=spring-svc param_loc=query
    private static void execSafeHandler(HttpExchange exchange) throws IOException {
        String command = query(exchange).getOrDefault("cmd", "hostname");
        if (!command.matches("[A-Za-z0-9 ._-]{1,64}")) {
            text(exchange, 400, "invalid command");
            return;
        }
        Process process = new ProcessBuilder("echo", command).redirectErrorStream(true).start();
        text(exchange, 200, readAll(process.getInputStream()));
    }

    private static String readAll(InputStream stream) throws IOException {
        StringBuilder builder = new StringBuilder();
        try (BufferedReader reader = new BufferedReader(new InputStreamReader(stream, StandardCharsets.UTF_8))) {
            String line;
            while ((line = reader.readLine()) != null) {
                builder.append(line).append('\n');
            }
        }
        return builder.toString();
    }

    // ─── Open redirect ─────────────────────────────────────────────────────

    // @vuln id=JAVA-009 name="Open redirect in logout handler" cwe=CWE-601 owasp=A01:2021 type=open-redirect level=1 param=url method=GET service=spring-svc url=/java/go param_loc=query needs_oob=false auth=false detection=active tags=redirect proof_kind=marker proof_desc="The Location header points to an arbitrary external host"
    private static void redirectHandler(HttpExchange exchange) throws IOException {
        String target = query(exchange).getOrDefault("url", "/");
        if (target.startsWith("http") || target.startsWith("//")) {
            labTrigger("JAVA-009", exchange, Map.of("payload", target));
        }
        exchange.getResponseHeaders().set("Location", target);
        exchange.sendResponseHeaders(302, -1);
        exchange.close();
    }

    // @control id=JAVA-009-C twin_of=JAVA-009 url=/java/go_safe method=GET param=url service=spring-svc param_loc=query
    private static void redirectSafeHandler(HttpExchange exchange) throws IOException {
        String target = query(exchange).getOrDefault("url", "/");
        if (!target.equals("/") && !target.equals("/java/download_safe")) {
            text(exchange, 400, "invalid redirect target");
            return;
        }
        exchange.getResponseHeaders().set("Location", target);
        exchange.sendResponseHeaders(302, -1);
        exchange.close();
    }

    // ─── Verbose errors ────────────────────────────────────────────────────

    // @vuln id=JAVA-010 name="Stack trace disclosure on application error" cwe=CWE-209 owasp=A05:2021 type=verbose-error level=1 param=input method=GET service=spring-svc url=/java/stack param_loc=query needs_oob=false auth=false detection=config tags=misconfiguration,info-leak proof_kind=marker proof_desc="Response contains the exception class, message and stack frames"
    private static void stackHandler(HttpExchange exchange) throws IOException {
        String input = query(exchange).getOrDefault("input", "");
        if (input.isEmpty()) {
            json(exchange, 200, "{\"status\":\"ok\"}");
            return;
        }

        Exception error = new IllegalStateException("failed to process: " + input);
        java.io.StringWriter writer = new java.io.StringWriter();
        error.printStackTrace(new java.io.PrintWriter(writer));

        labTrigger("JAVA-010", exchange, Map.of("input", input));
        text(exchange, 500, writer.toString());
    }

    // @control id=JAVA-010-C twin_of=JAVA-010 url=/java/stack_safe method=GET param=input service=spring-svc param_loc=query
    private static void stackSafeHandler(HttpExchange exchange) throws IOException {
        if (!query(exchange).getOrDefault("input", "").isEmpty()) {
            json(exchange, 400, "{\"error\":\"request could not be processed\",\"correlation_id\":\"a91f\"}");
            return;
        }
        json(exchange, 200, "{\"status\":\"ok\"}");
    }
}
