# Deploying Qwen3.5-9B on an A100 for NTAgentShield

## Recommended role

Run one text-only Qwen3.5-9B service as the bounded incident analyst. Detection, correlation, evidence storage and policy enforcement stay outside the model. This keeps the SOC functioning when inference is unavailable and prevents model output from becoming an unreviewed production command.

## vLLM service

The official Qwen3.5 model card documents vLLM serving, the Qwen reasoning parser, automatic tool choice, the `qwen3_coder` tool-call parser and a text-only mode that removes the vision encoder to free KV cache.

A practical A100 80 GB starting point is:

```bash
uv venv --python 3.11 .venv-qwen
source .venv-qwen/bin/activate
uv pip install vllm --torch-backend=auto \
  --extra-index-url https://wheels.vllm.ai/nightly

vllm serve Qwen/Qwen3.5-9B \
  --host 0.0.0.0 \
  --port 8000 \
  --dtype bfloat16 \
  --gpu-memory-utilization 0.88 \
  --max-model-len 65536 \
  --reasoning-parser qwen3 \
  --enable-auto-tool-choice \
  --tool-call-parser qwen3_coder \
  --language-model-only
```

Do not begin with 262,144 tokens for every request merely because the model supports it. Incident bundles should usually fit within 8K–32K tokens. A smaller operational limit improves concurrency, latency and memory headroom.

Configure NTAgentShield:

```dotenv
QWEN_ENABLED=true
QWEN_BASE_URL=http://A100_HOST:8000/v1
QWEN_API_KEY=EMPTY
QWEN_MODEL=Qwen/Qwen3.5-9B
QWEN_MAX_TOOL_ROUNDS=4
QWEN_TIMEOUT_SECONDS=90
```

For a remote endpoint, put a reverse proxy with mTLS or service authentication in front of vLLM. `EMPTY` is suitable only on an isolated trusted network.

## Resource behavior

The 9B BF16 weights require roughly 18 GB before runtime overhead and KV cache. An A100 80 GB leaves useful headroom, but actual concurrency depends on context length, output length, batching, vLLM version, and request shape. Validate capacity with workload-specific measurements.

Recommended operational controls:

- text-only mode
- request context cap
- maximum output tokens
- bounded tool rounds
- continuous batching
- queue depth and rejection metrics
- per-tenant rate limits in the application layer
- no direct public exposure

## Service isolation

- Run inference under a dedicated non-root account or container.
- Mount model weights read-only.
- Deny outbound internet unless model download or approved enrichment requires it.
- Keep the Qwen service separate from endpoint-agent credentials and response executors.
- Log request metadata, latency, token counts and error status. Avoid logging full sensitive prompts by default.
- Restrict the API to the hunt orchestrator network identity.

## Health and fallback

NTAgentShield detection does not depend on Qwen. When the model is disabled or unreachable:

- events continue to ingest
- baseline and behavior rules continue to run
- incidents continue to open
- deterministic evidence summaries remain available
- response policy remains enforced

Monitor:

- `/health` at NTAgentShield
- vLLM readiness and GPU memory
- request queue depth
- p50/p95 latency
- tool-call parsing errors
- invalid JSON rate
- unknown evidence-reference rate
- fallback analysis rate

## Suggested inference profile

Start with:

- temperature: `0.1`
- top-p: `0.85`
- maximum output: `2400` tokens
- maximum tool rounds: `4`
- initial evidence: incident events only
- tool result limit: `100` events
- investigation window: maximum ±24 hours around incident

Increase context only when evidence completeness requires it. Larger contexts increase latency and memory use and do not, by themselves, improve evidence quality.
