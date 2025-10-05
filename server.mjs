import { createServer } from 'node:http';
import { spawn } from 'node:child_process';
import { mkdir, writeFile, access } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';

import {
  diag,
  DiagConsoleLogger,
  DiagLogLevel,
  SpanStatusCode,
  trace
} from '@opentelemetry/api';
import { Resource } from '@opentelemetry/resources';
import { BatchSpanProcessor } from '@opentelemetry/sdk-trace-base';
import { NodeTracerProvider } from '@opentelemetry/sdk-trace-node';
import { OTLPTraceExporter } from '@opentelemetry/exporter-trace-otlp-http';
import { SemanticResourceAttributes } from '@opentelemetry/semantic-conventions';

const PORT = Number(process.env.PORT ?? 8787);
const WORKDIR = process.env.CLAUDE_CODE_WORKDIR ?? '/srv/claude-code/workspaces';

const OPENINFERENCE_ATTR = {
  INPUT_VALUE: 'input.value',
  INPUT_MIME_TYPE: 'input.mime_type',
  OUTPUT_VALUE: 'output.value',
  OUTPUT_MIME_TYPE: 'output.mime_type',
  LLM_MODEL_NAME: 'llm.model_name',
  LLM_PROVIDER: 'llm.provider',
  LLM_SYSTEM: 'llm.system',
  LLM_INPUT_MESSAGES: 'llm.input_messages',
  LLM_OUTPUT_MESSAGES: 'llm.output_messages',
  OPENINFERENCE_SPAN_KIND: 'openinference.span.kind',
};

const tracer = initializeTracing();

function initializeTracing() {
  if (globalThis.__CLAUDE_TRACER_INITIALIZED) {
    return trace.getTracer('claude-code-server');
  }

  try {
    diag.setLogger(new DiagConsoleLogger(), DiagLogLevel.ERROR);

    const resourceAttributes = parseResourceAttributes(process.env.OTEL_RESOURCE_ATTRIBUTES ?? '');

    const defaultServiceName = process.env.OTEL_SERVICE_NAME ?? 'claude-code-bifrost';
    if (!resourceAttributes[SemanticResourceAttributes.SERVICE_NAME]) {
      resourceAttributes[SemanticResourceAttributes.SERVICE_NAME] = defaultServiceName;
    }

    const resource = Resource.default().merge(new Resource(resourceAttributes));

    const exporter = new OTLPTraceExporter({
      url: resolveOtlpEndpoint(),
      headers: parseKeyValueHeader(process.env.OTEL_EXPORTER_OTLP_HEADERS)
    });

    const provider = new NodeTracerProvider({ resource });
    provider.addSpanProcessor(new BatchSpanProcessor(exporter));
    provider.register();

    globalThis.__CLAUDE_TRACER_INITIALIZED = true;
  } catch (error) {
    console.warn('[otel] failed to initialise tracing', error);
  }

  return trace.getTracer('claude-code-server');
}

function resolveOtlpEndpoint() {
  const explicit = process.env.OTEL_EXPORTER_OTLP_TRACES_ENDPOINT;
  if (explicit && explicit.trim().length > 0) {
    return explicit.trim();
  }

  const base = process.env.OTEL_EXPORTER_OTLP_ENDPOINT;
  if (base && base.trim().length > 0) {
    const normalised = base.endsWith('/') ? base.slice(0, -1) : base;
    return `${normalised}/v1/traces`;
  }

  return 'http://otel-collector:4318/v1/traces';
}

function parseResourceAttributes(raw) {
  const attributes = {};
  if (!raw) return attributes;

  for (const segment of raw.split(',')) {
    const idx = segment.indexOf('=');
    if (idx === -1) continue;
    const key = segment.slice(0, idx).trim();
    const value = segment.slice(idx + 1).trim();
    if (key && value) {
      attributes[key] = value;
    }
  }
  return attributes;
}

function parseKeyValueHeader(raw) {
  if (!raw) return undefined;
  const headers = {};
  for (const segment of raw.split(',')) {
    const idx = segment.indexOf('=');
    if (idx === -1) continue;
    const key = segment.slice(0, idx).trim();
    const value = segment.slice(idx + 1).trim();
    if (key && value) {
      headers[key] = value;
    }
  }
  return Object.keys(headers).length ? headers : undefined;
}

async function withSpan(name, options, fn) {
  const spanOptions = options ?? {};

  return new Promise((resolve, reject) => {
    tracer.startActiveSpan(name, spanOptions, async span => {
      try {
        const result = await fn(span);
        span.setStatus({ code: SpanStatusCode.OK });
        span.end();
        resolve(result);
      } catch (error) {
        span.recordException(error);
        span.setStatus({ code: SpanStatusCode.ERROR, message: error.message });
        span.end();
        reject(error);
      }
    });
  });
}
const server = createServer(async (req, res) => {
  if (req.method !== 'POST') {
    res.writeHead(405, { 'content-type': 'application/json' });
    res.end(JSON.stringify({ success: false, message: 'Only POST supported' }));
    return;
  }

  const requestAttributes = {
    'http.request.method': req.method,
    'http.route': req.url ?? '/'
  };

  if (req.socket?.remoteAddress) {
    requestAttributes['client.address'] = req.socket.remoteAddress;
  }

  try {
    await withSpan('claude.webhook', { attributes: requestAttributes }, async span => {
      const payload = await readBody(req);
      const requestLength = Buffer.byteLength(payload);
      span.setAttribute('http.request_content_length', requestLength);
      const body = JSON.parse(payload);

      const truncatedPayload = payload.length > OUTPUT_TRUNCATION_LIMIT ? `${payload.slice(0, OUTPUT_TRUNCATION_LIMIT)}…` : payload;
      span.setAttribute('http.request.body', truncatedPayload);
      span.setAttribute('http.request_body', truncatedPayload);
      span.addEvent('request.body', { 'request.body': truncatedPayload });

      span.setAttributes({
        'bifrost.repository': body.repository ?? '',
        'bifrost.request_id': body.requestId ?? ''
      });

      const envHints = body.environmentHints ?? {};
      const secrets = body.secrets ?? {};
      const containerCfg = body.adapter?.durableObject?.container ?? {};
      if (containerCfg.workdir) {
        span.setAttribute('bifrost.container.workdir', containerCfg.workdir);
      }

      await mkdir(WORKDIR, { recursive: true });

      const webhookPath = path.join(tmpdir(), 'agent-hacking-webhook.json');
      await writeFile(webhookPath, JSON.stringify(body, null, 2), 'utf-8');
      span.setAttribute('bifrost.webhook_path', webhookPath);

      const executionCwd = typeof containerCfg.workdir === 'string' ? containerCfg.workdir : WORKDIR;
      await mkdir(executionCwd, { recursive: true });
      span.setAttribute('process.cwd', executionCwd);

      const bifrostUrl =
        process.env.BIFROST_GATEWAY_URL ??
        `http://${process.env.BIFROST_HOST ?? '127.0.0.1'}:${process.env.BIFROST_PORT ?? '8080'}`;
      span.setAttribute('bifrost.gateway_url', bifrostUrl);

      const claudeServiceName = process.env.CLAUDE_CODE_OTEL_SERVICE_NAME ?? 'claude-code-runner';
      const claudeResourceAttrs =
        process.env.CLAUDE_CODE_OTEL_RESOURCE_ATTRIBUTES ??
        `service.name=${claudeServiceName},service.namespace=${process.env.OTEL_RESOURCE_NAMESPACE ?? 'agent-hacking'},service.instance.id=${process.env.HOSTNAME ?? 'claude-code-runner'}`;

      const anthropicBaseUrl = `${bifrostUrl.replace(/\/\/$/, '')}/anthropic`;

      const claudeEnv = {
        ...process.env,
        ...envHints,
        CLAUDE_CODE_WORKDIR: WORKDIR,
        CLAUDE_CODE_WEBHOOK_PATH: webhookPath,
        BIFROST_GATEWAY_URL: bifrostUrl,
        ANTHROPIC_API_URL: anthropicBaseUrl,
        ANTHROPIC_BASE_URL: anthropicBaseUrl,
        CLAUDE_CODE_GATEWAY_URL: bifrostUrl,
        CLAUDE_USE_API_KEYS: process.env.CLAUDE_USE_API_KEYS ?? 'true',
        OTEL_SERVICE_NAME: claudeServiceName,
        OTEL_RESOURCE_ATTRIBUTES: claudeResourceAttrs,
        ...mapSecretsToEnv(secrets),
      };

      const prompt = buildPrompt(body, containerCfg, executionCwd);
      span.setAttribute('bifrost.prompt.preview', prompt.slice(0, 120));

      const claudeModel = process.env.CLAUDE_CODE_MODEL ?? 'openrouter/x-ai/grok-4-fast';
      const llmProvider = inferProviderFromModel(claudeModel);
      const llmInputMessages = buildInputMessages(body, prompt);

      const claudeArgs = [
        '--print',
        '--output-format=stream-json',
        '--include-partial-messages',
        '--verbose',
        '--model', claudeModel,
        '--permission-mode', process.env.CLAUDE_CODE_PERMISSION_MODE ?? 'bypassPermissions',
        '--debug', 'api,http',
        ...((body.claudeArgs && Array.isArray(body.claudeArgs)) ? body.claudeArgs : []),
        prompt,
      ];
      span.setAttribute('bifrost.claude_args_length', claudeArgs.length);

      const claudeBinary =
        process.env.CLAUDE_CODE_BIN ||
        (await resolveClaudeBinary()) ||
        'claude';
      span.setAttribute('bifrost.claude_bin', claudeBinary);

      const claudeResult = await runCommand(claudeBinary, claudeArgs, {
        cwd: executionCwd,
        env: claudeEnv,
        forwardStdout: true,
        forwardStderr: true,
        otel: {
          inputMessages: llmInputMessages,
          inputValue: prompt,
          inputMimeType: 'text/plain',
          modelName: claudeModel,
          provider: llmProvider,
          spanKind: 'chain',
        },
      });
      const streamObjects = Array.isArray(claudeResult.streamObjects) ? claudeResult.streamObjects : [];
      const finalObject = Array.isArray(streamObjects)
        ? [...streamObjects].reverse().find(obj => obj?.type === 'result')
        : undefined;
      const responsePreview = finalObject
        ? JSON.stringify(finalObject)
        : (claudeResult.stdout?.length > OUTPUT_TRUNCATION_LIMIT
            ? `${claudeResult.stdout.slice(0, OUTPUT_TRUNCATION_LIMIT)}…`
            : claudeResult.stdout ?? '');
      if (responsePreview) {
        span.setAttribute('claude.response.body', responsePreview);
      }

      span.setAttribute('http.response.status_code', 200);

      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(
        JSON.stringify({
          success: true,
          message: 'Claude CLI completed',
          data: {
            repository: body.repository ?? null,
            exitCode: claudeResult.code,
          },
        })
      );
    });

  } catch (error) {
    console.error('[claude-code] execution failed', error);
    if (error?.stderr) {
      console.error('[claude-code] stderr:', error.stderr.toString());
    }
    const activeSpan = trace.getActiveSpan?.();
    if (activeSpan) {
      activeSpan.setAttribute('http.response.status_code', 500);
    }
    res.writeHead(500, { 'content-type': 'application/json' });
    res.end(
      JSON.stringify({
        success: false,
        message: error instanceof Error ? error.message : 'Unknown error',
      })
    );
  }
});

server.listen(PORT, () => {
  console.log(`[claude-code] listening on port ${PORT}`);
});

async function readBody(req) {
  const chunks = [];
  for await (const chunk of req) {
    chunks.push(chunk);
  }
  return Buffer.concat(chunks).toString('utf-8');
}

function buildPrompt(body, containerCfg, executionCwd) {
  const promptFromBody =
    typeof body.prompt === 'string' && body.prompt.trim().length > 0
      ? body.prompt.trim()
      : null;
  const promptFromContainer =
    typeof containerCfg.prompt === 'string' && containerCfg.prompt.trim().length > 0
      ? containerCfg.prompt.trim()
      : null;

  if (promptFromBody) return promptFromBody;
  if (promptFromContainer) return promptFromContainer;

  const checkoutPath = executionCwd ?? 'the repository workspace';
  return `Provide a brief summary of the repository at ${checkoutPath} and confirm the automation tunnel is healthy.`;
}

function buildInputMessages(body, prompt) {
  const messages = [];
  if (body && Array.isArray(body.messages)) {
    for (const rawMessage of body.messages) {
      if (!rawMessage || typeof rawMessage !== 'object') continue;
      const role = typeof rawMessage.role === 'string'
        ? rawMessage.role.toLowerCase()
        : 'user';
      const content = normaliseMessageContent(
        rawMessage.content ?? rawMessage.text ?? rawMessage.prompt
      );
      if (content) {
        messages.push({
          role,
          content: truncateValue(content, STREAM_SUMMARY_LIMIT),
        });
      }
    }
  }
  if (typeof prompt === 'string' && prompt.trim().length > 0) {
    const trimmedPrompt = prompt.trim();
    const alreadyPresent = messages.some(msg => msg.content === trimmedPrompt && msg.role === 'user');
    if (!alreadyPresent) {
      messages.push({
        role: 'user',
        content: truncateValue(trimmedPrompt, STREAM_SUMMARY_LIMIT),
      });
    }
  }
  return messages;
}

function normaliseMessageContent(content) {
  if (typeof content === 'string') {
    return content;
  }
  if (Array.isArray(content)) {
    return content
      .map(item => normaliseMessageContent(item))
      .filter(Boolean)
      .join('\n');
  }
  if (typeof content === 'object' && content !== null) {
    if (typeof content.text === 'string') {
      return content.text;
    }
    if (typeof content.content === 'string') {
      return content.content;
    }
    if (Array.isArray(content.content)) {
      return normaliseMessageContent(content.content);
    }
  }
  if (typeof content === 'number' || typeof content === 'boolean') {
    return String(content);
  }
  return '';
}

function inferProviderFromModel(modelName) {
  if (typeof modelName !== 'string' || modelName.trim().length === 0) {
    return undefined;
  }
  const [provider] = modelName.split('/');
  if (!provider || provider.trim().length === 0) {
    return undefined;
  }
  return provider.toLowerCase();
}

async function resolveClaudeBinary() {
  const candidates = [
    '/usr/local/bin/claude',
    '/usr/bin/claude',
    '/usr/local/bin/claude-code',
    '/usr/bin/claude-code'
  ];

  for (const candidate of candidates) {
    try {
      await access(candidate);
      return candidate;
    } catch {
      // continue
    }
  }
  return null;
}

function mapSecretsToEnv(secrets) {
  const env = {};
  const merged = { ...secrets };
  if (!merged?.OPENROUTER_API_KEY && process.env.OPENROUTER_API_KEY) {
    merged.OPENROUTER_API_KEY = process.env.OPENROUTER_API_KEY;
  }
  if (!merged?.GITHUB_TOKEN && process.env.GITHUB_TOKEN) {
    merged.GITHUB_TOKEN = process.env.GITHUB_TOKEN;
  }
  if (!merged?.GIT_ACCESS_TOKEN && process.env.GIT_ACCESS_TOKEN) {
    merged.GIT_ACCESS_TOKEN = process.env.GIT_ACCESS_TOKEN;
  }
  if (!merged?.CLAUDE_API_KEY && process.env.CLAUDE_API_KEY) {
    merged.CLAUDE_API_KEY = process.env.CLAUDE_API_KEY;
  }
  if (!merged?.ANTHROPIC_API_KEY && process.env.ANTHROPIC_API_KEY) {
    merged.ANTHROPIC_API_KEY = process.env.ANTHROPIC_API_KEY;
  }
  for (const [key, value] of Object.entries(merged ?? {})) {
    if (typeof value === 'string') {
      env[key] = value;
    }
  }
  return env;
}

const OUTPUT_TRUNCATION_LIMIT = 8192;
const STREAM_EVENT_LIMIT = 2048;
const STREAM_SUMMARY_LIMIT = 8192;

function emitStreamEvent(span, channel, text) {
  if (!text) return;
  const payload = text.length > STREAM_EVENT_LIMIT ? `${text.slice(0, STREAM_EVENT_LIMIT)}…` : text;
  span.addEvent(`process.${channel}.chunk`, { [`process.${channel}`]: payload });
}

function summariseStreamObject(obj) {
  const type = typeof obj?.type === 'string' ? obj.type : 'unknown';
  if (type === 'assistant' && Array.isArray(obj?.message?.content)) {
    const firstContent = obj.message.content.find(part => typeof part?.text === 'string')?.text ??
      obj.message.content.find(part => typeof part?.id === 'string')?.id ?? '';
    return `[assistant] ${firstContent}`;
  }
  if (type === 'tool') {
    return `[tool] ${obj?.name ?? 'unknown'}`;
  }
  if (type === 'system') {
   try {
      const prompt = obj?.prompt ?? obj?.uuid ?? '';
      return `[system] ${prompt}`;
    } catch {
      return `[system]`;
    }
  }
  if (typeof obj?.message?.content === 'string') {
    return `[${type}] ${obj.message.content}`;
  }
  if (typeof obj?.prompt === 'string') {
    return `[${type}] ${obj.prompt}`;
  }
  return `[${type}]`;
}

function recordStreamJson(span, line, seenSet, summaries, jsonAccumulator, messageCollector) {
  try {
    const parsed = JSON.parse(line);
    if (seenSet && seenSet.has(line)) return;
    if (seenSet) seenSet.add(line);
    const body = line.length > OUTPUT_TRUNCATION_LIMIT ? `${line.slice(0, OUTPUT_TRUNCATION_LIMIT)}…` : line;
    const attributes = {
      'claude.stream.body': body,
      'claude.stream.type': typeof parsed?.type === 'string' ? parsed.type : 'unknown'
    };
    if (typeof parsed?.role === 'string') {
      attributes['claude.stream.role'] = parsed.role;
    }
    if (typeof parsed?.tool === 'string') {
      attributes['claude.stream.tool'] = parsed.tool;
    }
    span.addEvent('claude.stream', attributes);
    if (summaries) {
      summaries.push(summariseStreamObject(parsed).slice(0, 512));
    }
    if (Array.isArray(jsonAccumulator)) {
      jsonAccumulator.push(parsed);
    }
    if (messageCollector) {
      const candidate = extractMessageFromStream(parsed);
      if (candidate) {
        messageCollector.add(candidate);
      }
    }
  } catch (error) {
    // Not JSON; ignore
  }
}

function runCommand(command, args, options = {}) {
  const attributes = {
    'process.command': command,
    'process.command_line': `${command} ${args.join(' ')}`,
    'process.working_directory': options.cwd ?? process.cwd()
  };

  return withSpan('claude.cli', { attributes }, span =>
    new Promise((resolve, reject) => {
      const otel = options.otel ?? {};
      annotateLlmInput(span, otel);
      const stdioInput = options.stdin ?? 'inherit';
      const child = spawn(command, args, {
        shell: false,
        stdio: [stdioInput, 'pipe', 'pipe'],
        cwd: options.cwd,
        env: options.env,
      });

      const forwardStdout = options.forwardStdout ?? true;
      const forwardStderr = options.forwardStderr ?? true;
      let stdout = '';
      let stderr = '';
      let stdoutLineBuffer = '';
      const emittedJson = new Set();
      const streamSummaries = [];
      const streamJsonObjects = [];
      const messageCollector = createMessageCollector();

      if (child.stdout) {
        child.stdout.on('data', chunk => {
          const text = chunk.toString();
          stdout += text;
          if (forwardStdout) process.stdout.write(text);
          emitStreamEvent(span, 'stdout', text);

          stdoutLineBuffer += text;
          let newlineIndex = stdoutLineBuffer.indexOf('\n');
          while (newlineIndex !== -1) {
            const line = stdoutLineBuffer.slice(0, newlineIndex).trim();
            stdoutLineBuffer = stdoutLineBuffer.slice(newlineIndex + 1);
            if (line.length > 0) {
              recordStreamJson(span, line, emittedJson, streamSummaries, streamJsonObjects, messageCollector);
            }
            newlineIndex = stdoutLineBuffer.indexOf('\n');
          }
        });
      }

      if (child.stderr) {
        child.stderr.on('data', chunk => {
          const text = chunk.toString();
          stderr += text;
          if (forwardStderr) process.stderr.write(text);
          emitStreamEvent(span, 'stderr', text);
        });
      }

      if (options.input && child.stdin && child.stdin.writable) {
        child.stdin.write(options.input);
        child.stdin.end();
      }

      child.on('close', code => {
        if (stdoutLineBuffer.trim().length > 0) {
          recordStreamJson(
            span,
            stdoutLineBuffer.trim(),
            emittedJson,
            streamSummaries,
            streamJsonObjects,
            messageCollector,
          );
        }
        span.setAttribute('process.exit_code', code ?? -1);
        if (stdout) {
          const truncated = stdout.length > OUTPUT_TRUNCATION_LIMIT ? `${stdout.slice(0, OUTPUT_TRUNCATION_LIMIT)}…` : stdout;
          span.addEvent('process.stdout', { 'process.stdout': truncated });
          for (const line of stdout.split(/\r?\n/)) {
            const trimmed = line.trim();
            if (trimmed.length === 0) continue;
            recordStreamJson(span, trimmed, emittedJson, streamSummaries, streamJsonObjects, messageCollector);
          }
        }
        if (stderr) {
          const truncated = stderr.length > OUTPUT_TRUNCATION_LIMIT ? `${stderr.slice(0, OUTPUT_TRUNCATION_LIMIT)}…` : stderr;
          span.addEvent('process.stderr', { 'process.stderr': truncated });
        }
        if (streamSummaries.length > 0) {
          const summaryPayload = JSON.stringify(streamSummaries);
          const truncatedSummary = summaryPayload.length > STREAM_SUMMARY_LIMIT ? `${summaryPayload.slice(0, STREAM_SUMMARY_LIMIT)}…` : summaryPayload;
          span.setAttribute('claude.streams', truncatedSummary);
        }
        const outputMessages = finalizeOutputMessages(messageCollector, streamSummaries, streamJsonObjects);
        if (outputMessages.length > 0) {
          setMessageAttributes(span, OPENINFERENCE_ATTR.LLM_OUTPUT_MESSAGES, outputMessages);
          const last = outputMessages[outputMessages.length - 1];
          if (last?.content) {
            span.setAttribute(OPENINFERENCE_ATTR.OUTPUT_VALUE, last.content);
            span.setAttribute(OPENINFERENCE_ATTR.OUTPUT_MIME_TYPE, 'text/plain');
          }
        }
        const success = code === 0;
        if (!success && !options.allowFailure) {
          const error = new Error(`${command} exited with code ${code}`);
          error.exitCode = code ?? -1;
          error.stdout = stdout;
          error.stderr = stderr;
          reject(error);
        } else {
          resolve({ success, code, stdout, stderr, streamObjects: streamJsonObjects, outputMessages });
        }
      });

      child.on('error', err => {
        if (stdout) {
          const truncated = stdout.length > OUTPUT_TRUNCATION_LIMIT ? `${stdout.slice(0, OUTPUT_TRUNCATION_LIMIT)}…` : stdout;
          span.addEvent('process.stdout', { 'process.stdout': truncated });
          for (const line of stdout.split(/\r?\n/)) {
            const trimmed = line.trim();
            if (trimmed.length === 0) continue;
            recordStreamJson(span, trimmed, emittedJson, streamSummaries, streamJsonObjects, messageCollector);
          }
        }
        if (stderr) {
          const truncated = stderr.length > OUTPUT_TRUNCATION_LIMIT ? `${stderr.slice(0, OUTPUT_TRUNCATION_LIMIT)}…` : stderr;
          span.addEvent('process.stderr', { 'process.stderr': truncated });
        }
        span.recordException(err);
        reject(err);
      });
    })
  );
}

function annotateLlmInput(span, otelOptions = {}) {
  if (!span || typeof otelOptions !== 'object') return;
  const {
    inputMessages,
    inputValue,
    inputMimeType,
    modelName,
    provider,
    system,
    spanKind
  } = otelOptions;

  if (Array.isArray(inputMessages) && inputMessages.length > 0) {
    setMessageAttributes(span, OPENINFERENCE_ATTR.LLM_INPUT_MESSAGES, inputMessages);
  }

  if (typeof inputValue === 'string' && inputValue.trim().length > 0) {
    span.setAttribute(OPENINFERENCE_ATTR.INPUT_VALUE, truncateValue(inputValue, OUTPUT_TRUNCATION_LIMIT));
    span.setAttribute(OPENINFERENCE_ATTR.INPUT_MIME_TYPE, inputMimeType ?? 'text/plain');
  } else if (typeof inputMimeType === 'string' && inputMimeType.trim().length > 0) {
    span.setAttribute(OPENINFERENCE_ATTR.INPUT_MIME_TYPE, inputMimeType);
  }

  if (typeof modelName === 'string' && modelName.trim().length > 0) {
    span.setAttribute(OPENINFERENCE_ATTR.LLM_MODEL_NAME, modelName);
  }

  if (typeof provider === 'string' && provider.trim().length > 0) {
    span.setAttribute(OPENINFERENCE_ATTR.LLM_PROVIDER, provider);
  }

  if (typeof system === 'string' && system.trim().length > 0) {
    span.setAttribute(OPENINFERENCE_ATTR.LLM_SYSTEM, system);
  }

  if (typeof spanKind === 'string' && spanKind.trim().length > 0) {
    span.setAttribute(OPENINFERENCE_ATTR.OPENINFERENCE_SPAN_KIND, spanKind.toUpperCase());
  }
}

function createMessageCollector(limit = STREAM_SUMMARY_LIMIT) {
  const seen = new Set();
  const messages = [];
  return {
    add(message) {
      if (!message || typeof message !== 'object') return;
      const role = typeof message.role === 'string' && message.role.trim().length > 0
        ? message.role.toLowerCase()
        : 'assistant';
      const rawContent = normaliseMessageContent(message.content ?? message.text ?? '');
      const content = rawContent ? truncateValue(rawContent.trim(), limit) : '';
      if (!content) return;
      const dedupeKey = `${role}::${content}`;
      if (seen.has(dedupeKey)) return;
      seen.add(dedupeKey);
      messages.push({ role, content });
    },
    values() {
      return [...messages];
    }
  };
}

function setMessageAttributes(span, baseKey, messages) {
  if (!span || !Array.isArray(messages) || messages.length === 0) return;
  messages.forEach((message, messageIndex) => {
    if (!message || typeof message !== 'object') return;
    const role = typeof message.role === 'string' && message.role.trim().length > 0
      ? message.role.toLowerCase()
      : 'assistant';
    const content = normaliseMessageContent(message.content ?? message.text ?? '');
    span.setAttribute(`${baseKey}.${messageIndex}.message.role`, role);
    if (content) {
      span.setAttribute(
        `${baseKey}.${messageIndex}.message.content`,
        truncateValue(content, STREAM_SUMMARY_LIMIT)
      );
    }
    if (Array.isArray(message.contents)) {
      message.contents.forEach((part, partIndex) => {
        if (!part || typeof part !== 'object') return;
        const type = typeof part.type === 'string' ? part.type : undefined;
        const text = normaliseMessageContent(part.text ?? part.content ?? '');
        if (type) {
          span.setAttribute(
            `${baseKey}.${messageIndex}.message.contents.${partIndex}.message_content.type`,
            type
          );
        }
        if (text) {
          span.setAttribute(
            `${baseKey}.${messageIndex}.message.contents.${partIndex}.message_content.text`,
            truncateValue(text, STREAM_EVENT_LIMIT)
          );
        }
      });
    }
  });
}

function finalizeOutputMessages(messageCollector, streamSummaries, streamJsonObjects) {
  const collected = messageCollector && typeof messageCollector.values === 'function'
    ? messageCollector.values()
    : [];
  const dedupe = new Set();
  const messages = [];

  const pushMessage = (role, content) => {
    if (!content) return;
    const normalisedRole = role && typeof role === 'string' && role.trim().length > 0
      ? role.toLowerCase()
      : 'assistant';
    const truncated = truncateValue(content.trim(), STREAM_SUMMARY_LIMIT);
    if (!truncated) return;
    const key = `${normalisedRole}::${truncated}`;
    if (dedupe.has(key)) return;
    dedupe.add(key);
    messages.push({ role: normalisedRole, content: truncated });
  };

  collected.forEach(message => pushMessage(message.role, message.content));

  const finalText = extractFinalText(streamJsonObjects);
  if (finalText) {
    pushMessage('assistant', finalText);
  }

  if (messages.length === 0 && Array.isArray(streamJsonObjects)) {
    for (const obj of streamJsonObjects) {
      const candidate = extractMessageFromStream(obj);
      if (candidate) {
        pushMessage(candidate.role, candidate.content);
      }
    }
  }

  if (messages.length === 0 && Array.isArray(streamSummaries)) {
    for (const summary of streamSummaries) {
      const candidate = parseSummaryMessage(summary);
      if (candidate) {
        pushMessage(candidate.role, candidate.content);
      }
    }
  }

  return messages;
}

function extractMessageFromStream(obj) {
  if (!obj || typeof obj !== 'object') return null;
  let role = typeof obj?.message?.role === 'string'
    ? obj.message.role
    : typeof obj.role === 'string'
      ? obj.role
      : undefined;

  let content = normaliseMessageContent(
    obj?.message?.content ??
    obj?.content ??
    obj?.text ??
    obj?.delta?.text ??
    obj?.output ??
    obj?.output_text ??
    obj?.message?.text ??
    ''
  );

  if (!content && typeof obj.result === 'string') {
    content = obj.result;
  }

  if (!content && typeof obj?.delta?.display === 'string') {
    content = obj.delta.display;
  }

  if (!role) {
    const type = typeof obj.type === 'string' ? obj.type.toLowerCase() : '';
    if (type.includes('tool')) role = 'tool';
    else if (type.includes('assistant')) role = 'assistant';
    else if (type.includes('system')) role = 'system';
    else if (type.includes('user')) role = 'user';
  }

  if (!content || content.trim().length === 0) {
    return null;
  }

  return {
    role: (role ?? 'assistant').toLowerCase(),
    content: content.trim()
  };
}

function extractFinalText(streamJsonObjects) {
  if (!Array.isArray(streamJsonObjects)) return undefined;
  for (let index = streamJsonObjects.length - 1; index >= 0; index -= 1) {
    const obj = streamJsonObjects[index];
    if (!obj || typeof obj !== 'object') continue;
    if (typeof obj.result === 'string' && obj.result.trim().length > 0) {
      return truncateValue(obj.result.trim(), OUTPUT_TRUNCATION_LIMIT);
    }
    if (typeof obj?.message === 'string' && obj.message.trim().length > 0) {
      return truncateValue(obj.message.trim(), OUTPUT_TRUNCATION_LIMIT);
    }
    const messageContent = normaliseMessageContent(obj?.message?.content ?? obj?.content ?? '');
    if (messageContent && messageContent.trim().length > 0) {
      return truncateValue(messageContent.trim(), OUTPUT_TRUNCATION_LIMIT);
    }
  }
  return undefined;
}

function parseSummaryMessage(summary) {
  if (typeof summary !== 'string') return null;
  const trimmed = summary.trim();
  if (!trimmed) return null;
  const match = trimmed.match(/^\[([^\]]+)\]\s*(.*)$/);
  if (match) {
    const [, role, rest] = match;
    const content = rest ?? '';
    return {
      role: role.toLowerCase(),
      content: truncateValue(content || role, STREAM_SUMMARY_LIMIT),
    };
  }
  return {
    role: 'assistant',
    content: truncateValue(trimmed, STREAM_SUMMARY_LIMIT),
  };
}

function truncateValue(value, limit = OUTPUT_TRUNCATION_LIMIT) {
  if (typeof value !== 'string') {
    value = String(value ?? '');
  }
  if (value.length <= limit) return value;
  return `${value.slice(0, limit)}…`;
}
