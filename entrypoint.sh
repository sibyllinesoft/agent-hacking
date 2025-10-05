#!/usr/bin/env bash
set -euo pipefail

BIFROST_ENABLED="${BIFROST_ENABLED:-1}"
BIFROST_HOST="${BIFROST_HOST:-0.0.0.0}"
BIFROST_PORT="${BIFROST_PORT:-8080}"
BIFROST_APP_DIR="${BIFROST_APP_DIR:-/srv/claude-code/bifrost}"
BIFROST_CONFIG_PATH="${BIFROST_CONFIG_PATH:-/srv/claude-code/bifrost.config.json}"
BIFROST_BINARY="${BIFROST_BINARY:-bifrost}"
APP_USER="${APP_USER:-claude}"
APP_GROUP="${APP_GROUP:-$APP_USER}"
APP_HOME=$(getent passwd "${APP_USER}" | cut -d: -f6)
if [[ -z "${APP_HOME}" ]]; then
  echo "[entrypoint] unable to determine home directory for ${APP_USER}" >&2
  exit 1
fi
BIFROST_USER_CONFIG="${BIFROST_USER_CONFIG:-${APP_HOME}/.config/bifrost}"
CLAUDE_CODE_WORKDIR="${CLAUDE_CODE_WORKDIR:-/srv/claude-code/workspaces}"
XDG_CONFIG_ROOT=$(dirname "${BIFROST_USER_CONFIG}")
mkdir -p "${BIFROST_APP_DIR}" "${CLAUDE_CODE_WORKDIR}" "${BIFROST_USER_CONFIG}"
export XDG_CONFIG_HOME="${XDG_CONFIG_ROOT}"
export HOME="${APP_HOME}"

# Ensure globally installed npm binaries (claude-code) are on PATH
export PATH="/usr/local/bin:$PATH"

if [[ -f "${BIFROST_CONFIG_PATH}" ]]; then
  cp -f "${BIFROST_CONFIG_PATH}" "${BIFROST_APP_DIR}/config.json"
  cp -f "${BIFROST_CONFIG_PATH}" "${BIFROST_USER_CONFIG}/config.json"
fi

chown -R "${APP_USER}:${APP_GROUP}" "${BIFROST_APP_DIR}" "${CLAUDE_CODE_WORKDIR}" "${XDG_CONFIG_ROOT}"

# Load local secrets for OpenRouter when available
if [[ -z "${OPENROUTER_API_KEY:-}" ]] && [[ -f "/run/secrets/openrouter_api_key" ]]; then
  export OPENROUTER_API_KEY=$(< /run/secrets/openrouter_api_key)
fi

if [[ -z "${CLAUDE_API_KEY:-}" ]] && [[ -n "${OPENROUTER_API_KEY:-}" ]]; then
  export CLAUDE_API_KEY="${OPENROUTER_API_KEY}"
fi

if [[ -z "${ANTHROPIC_API_KEY:-}" ]] && [[ -n "${OPENROUTER_API_KEY:-}" ]]; then
  export ANTHROPIC_API_KEY="${OPENROUTER_API_KEY}"
fi

export CLAUDE_CODE_PERMISSION_MODE="${CLAUDE_CODE_PERMISSION_MODE:-bypassPermissions}"

# Ensure reasonable defaults for OTEL export so traces are emitted when collector is attached
export OTEL_SERVICE_NAME="${OTEL_SERVICE_NAME:-claude-code-bifrost}"
BASE_OTEL_ATTRIBUTES="service.name=${OTEL_SERVICE_NAME},service.namespace=${OTEL_RESOURCE_NAMESPACE:-agent-hacking},service.instance.id=${HOSTNAME:-claude-code}"
if [[ -n "${OTEL_RESOURCE_ATTRIBUTES:-}" ]]; then
  export OTEL_RESOURCE_ATTRIBUTES="${BASE_OTEL_ATTRIBUTES},${OTEL_RESOURCE_ATTRIBUTES}"
else
  export OTEL_RESOURCE_ATTRIBUTES="${BASE_OTEL_ATTRIBUTES}"
fi

NODE_OTEL_ENDPOINT="${NODE_OTEL_ENDPOINT:-http://otel-collector:4318}"
# ensure we only add /v1/traces once
if [[ "${NODE_OTEL_ENDPOINT}" =~ /v1/traces$ ]]; then
  NODE_OTEL_TRACES_ENDPOINT="${NODE_OTEL_ENDPOINT}"
else
  NODE_OTEL_TRACES_ENDPOINT="${NODE_OTEL_TRACES_ENDPOINT:-${NODE_OTEL_ENDPOINT%/}/v1/traces}"
fi

terminate_pid() {
  local pid="$1"
  if [[ -n "${pid}" ]] && kill -0 "${pid}" 2>/dev/null; then
    kill "${pid}" 2>/dev/null || true
    for _ in {1..20}; do
      if ! kill -0 "${pid}" 2>/dev/null; then
        wait "${pid}" 2>/dev/null || true
        return
      fi
      sleep 0.5
    done
    echo "[entrypoint] process ${pid} did not shut down gracefully, forcing termination"
    kill -9 "${pid}" 2>/dev/null || true
    wait "${pid}" 2>/dev/null || true
  fi
}

cleanup() {
  terminate_pid "${NODE_PID:-}"
  terminate_pid "${BIFROST_PID:-}"
  terminate_pid "${OTEL_AUTOINSTRUMENT_PID:-}"
}

handle_signal() {
  cleanup
  exit 0
}

trap handle_signal SIGINT SIGTERM

if [[ "${BIFROST_ENABLED}" != "0" ]]; then
  echo "[entrypoint] Starting Bifrost gateway on ${BIFROST_HOST}:${BIFROST_PORT}"
  extra_args=()
  if [[ -n "${BIFROST_EXTRA_ARGS:-}" ]]; then
    # Allow the caller to supply additional CLI flags (e.g. '--profile debug').
    # shellcheck disable=SC2206
    extra_args=(${BIFROST_EXTRA_ARGS})
  fi

  gosu "${APP_USER}" env HOME="${APP_HOME}" XDG_CONFIG_HOME="${XDG_CONFIG_HOME}" "${BIFROST_BINARY}" http \
    --host "${BIFROST_HOST}" \
    --port "${BIFROST_PORT}" \
    --app-dir "${BIFROST_APP_DIR}" \
    --log-level "${BIFROST_LOG_LEVEL:-debug}" \
    --log-style "${BIFROST_LOG_STYLE:-pretty}" \
    ${extra_args[@]} &
  BIFROST_PID=$!
else
  echo "[entrypoint] Bifrost gateway disabled via BIFROST_ENABLED=0"
fi

# Launch Go auto-instrumentation for Bifrost when available.
if [[ -x "/usr/local/bin/otel-go-instrumentation" ]]; then
  if [[ "${BIFROST_ENABLE_OTEL_AUTOINSTRUMENTATION:-1}" != "0" ]]; then
    BIFROST_OTEL_ENDPOINT="${BIFROST_OTEL_EXPORTER_ENDPOINT:-http://otel-collector:4318}"
    if [[ "${BIFROST_OTEL_EXPORTER_PROTOCOL:-http/protobuf}" =~ grpc ]]; then
      BIFROST_OTEL_TRACES_ENDPOINT="${BIFROST_OTEL_TRACES_ENDPOINT:-${BIFROST_OTEL_ENDPOINT}}"
    else
      if [[ "${BIFROST_OTEL_TRACES_ENDPOINT:-}" =~ /v1/traces$ ]]; then
        BIFROST_OTEL_TRACES_ENDPOINT="${BIFROST_OTEL_TRACES_ENDPOINT}"
      else
        BIFROST_OTEL_TRACES_ENDPOINT="${BIFROST_OTEL_TRACES_ENDPOINT:-${BIFROST_OTEL_ENDPOINT%/}/v1/traces}"
      fi
    fi

    echo "[entrypoint] Launching otel-go-instrumentation for bifrost"
    INSTRUMENT_SERVICE_NAME="${BIFROST_OTEL_SERVICE_NAME:-bifrost-gateway}"
    INSTRUMENT_RESOURCE_ATTRIBUTES="service.name=${INSTRUMENT_SERVICE_NAME},service.namespace=${OTEL_RESOURCE_NAMESPACE:-agent-hacking},service.instance.id=${HOSTNAME:-bifrost-gateway}"
    OTEL_GO_AUTO_TARGET_EXE="${BIFROST_AUTOINSTRUMENT_TARGET_EXE:-/tmp/bifrost-http-0}" \
    OTEL_EXPORTER_OTLP_ENDPOINT="${BIFROST_OTEL_ENDPOINT}" \
    OTEL_EXPORTER_OTLP_TRACES_ENDPOINT="${BIFROST_OTEL_TRACES_ENDPOINT}" \
    OTEL_EXPORTER_OTLP_PROTOCOL="${BIFROST_OTEL_EXPORTER_PROTOCOL:-http/protobuf}" \
    OTEL_EXPORTER_OTLP_INSECURE="true" \
    OTEL_PROPAGATORS="${BIFROST_OTEL_PROPAGATORS:-tracecontext,baggage}" \
    OTEL_SERVICE_NAME="${INSTRUMENT_SERVICE_NAME}" \
    OTEL_RESOURCE_ATTRIBUTES="${INSTRUMENT_RESOURCE_ATTRIBUTES}" \
    /usr/local/bin/otel-go-instrumentation >/proc/1/fd/1 2>/proc/1/fd/2 &
    OTEL_AUTOINSTRUMENT_PID=$!
  fi
fi

# Give the gateway a moment to boot when running in ultra-lightweight environments
if [[ -n "${BIFROST_PID:-}" ]]; then
  for _ in {1..30}; do
    if curl -sf "http://${BIFROST_HOST}:${BIFROST_PORT}/healthz" >/dev/null 2>&1; then
      break
    fi
    sleep 0.5
  done
fi

gosu "${APP_USER}" env \
  HOME="${APP_HOME}" \
  XDG_CONFIG_HOME="${XDG_CONFIG_HOME}" \
  OTEL_EXPORTER_OTLP_ENDPOINT="${NODE_OTEL_ENDPOINT}" \
  OTEL_EXPORTER_OTLP_TRACES_ENDPOINT="${NODE_OTEL_TRACES_ENDPOINT}" \
  OTEL_EXPORTER_OTLP_PROTOCOL="http/protobuf" \
  OTEL_EXPORTER_OTLP_INSECURE="true" \
  node server.mjs "$@" &
NODE_PID=$!

wait $NODE_PID
status=$?
cleanup
exit $status
