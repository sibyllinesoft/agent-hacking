# Agent Hacking: Claude Code + Bifrost Observability Demo

This repo shows how to layer **Bifrost** in front of Claude Code so you can send requests through any provider while emitting OpenTelemetry traces. The included Docker assets start a Claude Code container with Bifrost plus a lightweight, unopinionated observability stack (OpenTelemetry Collector, ClickHouse, Grafana Tempo, and Grafana) so you can see traces end-to-end without additional wiring.

## What you get

- Claude Code CLI packaged with Bifrost and sensible defaults for OTLP export
- Bifrost configuration that forwards `anthropic` traffic to OpenRouter (swap in your own keys/providers)
- `docker-compose` stack with
  - `claude-code`: Claude Code + Bifrost + OTEL setup (blank workspace)
  - `otel-collector`: ships spans to ClickHouse and Tempo
  - `clickhouse`: persists traces for later analysis
  - `tempo`: Grafana Tempo store for long-lived traces
  - `grafana`: UI for exploring traces (pre-wired to Tempo)

## Prerequisites

- Docker + Docker Compose v2
- API key for a compatible service (OpenRouter works out of the box)

## Quick start

1. Provide credentials:

   ```bash
   cp .env.example .env
   echo "OPENROUTER_API_KEY=sk-..." >> .env
   # Optional: add ANTHROPIC_API_KEY / CLAUDE_API_KEY entries if you want to
   # bypass OpenRouter and point straight at Anthropic.
   ```

   (If you prefer exporting variables directly, the compose file still honours
   `OPENROUTER_API_KEY` from your shell environment.)

2. Build and launch the stack:

   ```bash
   docker compose up --build
   ```

   (The `claude-code` service runs with `privileged: true` so the bundled Go auto-instrumentation can attach to the Bifrost process. Drop `BIFROST_ENABLE_OTEL_AUTOINSTRUMENTATION=0` in `.env` if you need a non-privileged run.)

3. Trigger Claude Code via the built-in webhook server. The workspace starts empty so you can demonstrate git operations from the agent itself; this example simply asks for a summary:

   ```bash
   curl -X POST http://localhost:8787/ \
     -H 'content-type: application/json' \
     -d '{"prompt":"List the files in the current workspace and exit."}'
   ```

4. Explore telemetry:

   - Grafana UI: http://localhost:6300 (default credentials `admin`/`admin`).
     1. Open **Explore → Traces** and pick the **Tempo** data source.
     2. Expand the time range to **Last 15 minutes** (or longer if required).
     3. Run a TraceQL query such as `{ service.name = "claude-code-bifrost" }` to list recent webhook executions.
     4. Click any trace to inspect the `claude.webhook`/`claude.cli` spans, request payload, agent/tool turns, and final response inside the **Attributes** tab.
     5. To focus on gateway traffic, swap the query to `{ service.name = "bifrost-gateway" }`.
   - Tempo REST API: http://localhost:3200/api/search?limit=5 returns the most recent trace IDs if you prefer ad-hoc checks.
   - ClickHouse HTTP: http://localhost:8123 (database `otel`) for SQL access to raw span/event data.
   - OTLP endpoints exposed on `localhost:4317` (gRPC) and `4318` (HTTP) if you want to plug in extra tooling.

The Claude Code container listens on port `8787` and forwards Anthropics API calls through Bifrost (exposed on host port `6080` and forwarded to container port `8080`). Bifrost rewrites requests to the configured provider, exports OTLP traces to the bundled collector, and enriches spans with telemetry. In your demos, prompt Claude Code to `git clone` whichever repository you want to explore—the container leaves the workspace untouched on purpose.

Telemetry sanity checks:

- `docker compose exec clickhouse clickhouse-client --query "SELECT toString(Timestamp), ServiceName, SpanName, StatusCode FROM otel.otel_traces ORDER BY Timestamp DESC LIMIT 5"`
- Grafana Explore: open http://localhost:6300 → **Explore → Traces**, choose the `Tempo` data source, and run a TraceQL query like `{ service.name = "claude-code-bifrost" }` to list recent spans.
- All webhook invocations emit two spans (`claude.webhook`, `claude.cli`) regardless of downstream provider success, making it easy to verify the pipeline even without API keys.
- The stack also auto-instruments the Bifrost binary via `otel-go-instrumentation`. You will see additional spans under `service.name=bifrost-gateway` representing every Anthropics-compatible call the gateway forwards. Disable this behaviour with `BIFROST_ENABLE_OTEL_AUTOINSTRUMENTATION=0` if you do not want the container to run with elevated privileges.

### Example agent requests

Once the stack is running you can exercise the agent with plain `curl` calls. Each call returns a JSON result and emits spans you can inspect in Grafana (Tempo) or ClickHouse.

**List files in the workspace**

```bash
curl -s -o /tmp/claude-list.json -w "\nHTTP %\{http_code\}\n" \
  http://localhost:8787 \
  -H 'content-type: application/json' \
  -d '{"prompt":"List the files in the current workspace and exit."}'
cat /tmp/claude-list.json | jq
```

**Run a multi-step workflow**

```bash
curl -s -o /tmp/claude-steps.json -w "\nHTTP %\{http_code\}\n" \
  http://localhost:8787 \
  -H 'content-type: application/json' \
  -d '{"prompt":"In multiple steps create a file hello.txt containing hello world, list the directory after each step, and finally cat the file."}'
cat /tmp/claude-steps.json | jq '.data'
```

### Example ClickHouse queries

Use the embedded ClickHouse shell to inspect the spans that were generated:

```bash
# Show the most recent Claude CLI span (final response + turn summaries + stream events)
docker compose exec clickhouse clickhouse-client --query "
  SELECT
    Timestamp,
    SpanAttributes['claude.response.body']   AS final_response,
    SpanAttributes['claude.streams']         AS turn_summaries,
    arrayStringConcat(
      arrayMap(
        x -> concat(tupleElement(x, 1), ': ', tupleElement(x, 2)['claude.stream.body']),
        arrayFilter(
          x -> tupleElement(x, 1) = 'claude.stream',
          arrayZip(Events.Name, Events.Attributes)
        )
      ),
      '\n'
    ) AS stream_events
  FROM otel.otel_traces
  WHERE ServiceName = 'claude-code-bifrost'
    AND SpanName    = 'claude.cli'
  ORDER BY Timestamp DESC
  LIMIT 1;
"

# Show the matching gateway span emitted by Bifrost
docker compose exec clickhouse clickhouse-client --query "
  SELECT Timestamp, SpanAttributes['http.request.body'], SpanAttributes['http.response.status_code']
  FROM otel.otel_traces
  WHERE ServiceName = 'bifrost-gateway'
  ORDER BY Timestamp DESC
  LIMIT 1;
"
```

## Repo layout

```
Dockerfile              Claude Code + Bifrost image
bifrost.config.json     Provider routing and telemetry plugin settings
entrypoint.sh           Boots Bifrost then the Claude Code server with OTEL defaults
server.mjs              Minimal webhook server that shells out to the Claude CLI
playbooks/              Example automation playbook used by the server
observability/          OpenTelemetry Collector + ClickHouse bootstrap configs
docker-compose.yaml     One-command demo environment
```

## Customising providers

Bifrost reads `bifrost.config.json` at startup. You can swap `openrouter` for other providers and adjust model lists. Secrets can be supplied through environment variables or Docker secrets; the entrypoint automatically falls back to `OPENROUTER_API_KEY` for both `ANTHROPIC_API_KEY` and `CLAUDE_API_KEY` if they are unset.

To override Bifrost flags at runtime, set `BIFROST_EXTRA_ARGS` in `docker-compose.yaml` (for example `--profile debug`).

## Observability notes

- The Dockerfile sets `OTEL_SERVICE_NAME=claude-code-bifrost` by default; tweak via environment variables in `docker-compose.yaml` if you spin up multiple instances.
- The OpenTelemetry Collector forwards spans to ClickHouse and Tempo. ClickHouse is initialised with a minimal schema in `observability/clickhouse-init.sql`.
- Because the collector exposes OTLP ports publicly, you can point other workloads at `http://localhost:4318` to reuse this stack for additional experiments.
- Grafana (pre-provisioned with a Tempo data source) honours the OpenInference span attributes emitted by the server. Expand a `claude.cli` span to view full request bodies, the final response, and each agent/tool turn rendered in the trace view.

## Next steps

- Instruct Claude Code to clone any repository you want to showcase once the session starts.
- Extend the `playbooks/` folder with richer automation scripts for your demos.
- Add additional Grafana dashboards or connect alternative OTLP consumers if you want dashboards beyond the bundled Explore view.
