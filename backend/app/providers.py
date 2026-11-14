"""Provider calls are isolated here so tests can replace them without network access."""
import os
import ipaddress
import math
import json
import inspect
import uuid
import asyncio
from dataclasses import replace
from functools import partial
from datetime import datetime
from urllib.parse import urlsplit
import httpx
from openai import AsyncStream
# LiteLLM may otherwise fetch tokenizer/catalog assets independently of the
# configured provider. Offline mode leaves explicit provider calls enabled.
os.environ['LITELLM_OFFLINE_MODE'] = 'true'
os.environ.setdefault("LITELLM_LOCAL_MODEL_COST_MAP", "True")
import litellm
from litellm.litellm_core_utils.litellm_logging import Logging
litellm.telemetry = False

def provider_timeout() -> float:
    try:
        value = float(os.environ.get('MAGPIE_PROVIDER_TIMEOUT_SECONDS', '60'))
    except ValueError:
        raise ValueError('MAGPIE_PROVIDER_TIMEOUT_SECONDS must be between 1 and 3600') from None
    if not math.isfinite(value) or not 1 <= value <= 3600:
        raise ValueError('MAGPIE_PROVIDER_TIMEOUT_SECONDS must be between 1 and 3600')
    return value


UPSTREAM_TIMEOUT_SECONDS = provider_timeout()

PROVIDERS = {
    "openai": {"name": "OpenAI", "prefix": "openai", "base": None},
    "anthropic": {"name": "Anthropic", "prefix": "anthropic", "base": None},
    "gemini": {"name": "Google Gemini", "prefix": "gemini", "base": None},
    "xai": {"name": "xAI · Grok", "prefix": "xai", "base": None},
    "openrouter": {"name": "OpenRouter", "prefix": "openrouter", "base": None},
    "deepseek": {"name": "DeepSeek", "prefix": "deepseek", "base": None},
    "groq": {"name": "Groq", "prefix": "groq", "base": None},
    "cerebras": {"name": "Cerebras", "prefix": "cerebras", "base": None},
    "mistral": {"name": "Mistral AI", "prefix": "mistral", "base": None},
    "together_ai": {"name": "Together AI", "prefix": "together_ai", "base": None},
    "fireworks_ai": {"name": "Fireworks AI", "prefix": "fireworks_ai", "base": None},
    "nvidia_nim": {"name": "NVIDIA NIM", "prefix": "nvidia_nim", "base": None},
    "moonshot": {"name": "Moonshot · 기본", "prefix": "moonshot", "base": None},
    "moonshot_global": {"name": "Moonshot · 글로벌", "prefix": "moonshot", "base": "https://api.moonshot.ai/v1"},
    "moonshot_china": {"name": "Moonshot · 중국", "prefix": "moonshot", "base": "https://api.moonshot.cn/v1"},
    "kimi_coding_global": {"name": "Kimi Code · 글로벌", "prefix": "openai", "base": "https://api.kimi.ai/coding/v1"},
    "kimi_coding_china": {"name": "Kimi Code · 중국", "prefix": "openai", "base": "https://api.kimi.com/coding/v1"},
    "qwen_singapore": {"name": "Alibaba / Qwen · 싱가포르", "prefix": "openai", "base": "https://dashscope-intl.aliyuncs.com/compatible-mode/v1"},
    "qwen_china": {"name": "Alibaba / Qwen · 중국 베이징", "prefix": "openai", "base": "https://dashscope.aliyuncs.com/compatible-mode/v1"},
    "siliconflow_global": {"name": "SiliconFlow · 글로벌", "prefix": "openai", "base": "https://api.siliconflow.com/v1"},
    "siliconflow_china": {"name": "SiliconFlow · 중국", "prefix": "openai", "base": "https://api.siliconflow.cn/v1"},
    "minimax_global": {"name": "MiniMax · 글로벌", "prefix": "minimax", "base": "https://api.minimax.io/v1"},
    "minimax_china": {"name": "MiniMax · 중국", "prefix": "minimax", "base": "https://api.minimaxi.com/v1"},
    "novita": {"name": "Novita AI", "prefix": "novita", "base": None},
    "chutes": {"name": "Chutes", "prefix": "chutes", "base": None},
    "synthetic": {"name": "Synthetic", "prefix": "synthetic", "base": None},
    "venice": {"name": "Venice AI", "prefix": "openai", "base": "https://api.venice.ai/api/v1"},
    "zai": {"name": "Z.AI", "prefix": "zai", "base": None},
    "bigmodel": {"name": "Zhipu GLM", "prefix": "bigmodel", "base": None},
    "zai_coding": {"name": "Z.AI · 글로벌 Coding Plan", "prefix": "openai", "base": "https://api.z.ai/api/coding/paas/v4"},
    "bigmodel_coding": {"name": "Zhipu GLM · 중국 Coding Plan", "prefix": "openai", "base": "https://open.bigmodel.cn/api/coding/paas/v4"},
    "perplexity": {"name": "Perplexity", "prefix": "perplexity", "base": None},
    "sambanova": {"name": "SambaNova", "prefix": "sambanova", "base": None},
    "typesafe": {"name": "TypeSafe Jev", "prefix": "typesafe", "base": None},
    "openai_compatible": {"name": "OpenAI 호환 (허용 목록)", "prefix": "openai", "base": None},
    "exaone": {"name": "EXAONE", "prefix": "openai", "base": "https://api.exaone.ai/v1"},
}

CODING_PROVIDERS = frozenset({'kimi_coding_global', 'kimi_coding_china', 'zai_coding', 'bigmodel_coding'})

# Explicit endpoints avoid deriving destinations from a client request. Some
# providers do not expose a model catalog; their models remain manually usable.
DISCOVERY_BASES = {
    'openai': 'https://api.openai.com/v1',
    'anthropic': 'https://api.anthropic.com/v1',
    'gemini': 'https://generativelanguage.googleapis.com/v1beta',
    'typesafe': 'https://api.typesafe.ai/v1',
    'xai': 'https://api.x.ai/v1',
    'openrouter': 'https://openrouter.ai/api/v1',
    'deepseek': 'https://api.deepseek.com',
    'groq': 'https://api.groq.com/openai/v1',
    'mistral': 'https://api.mistral.ai/v1',
}


class DiscoveryError(Exception):
    def __init__(self, code: str):
        self.code = code


async def discover_models(provider_type: str, secret: str, custom_base: str | None = None):
    """Fetch bounded pages on explicit request; never follow redirects."""
    if provider_type in CODING_PROVIDERS:
        raise DiscoveryError('unsupported')
    if provider_type == 'openai_compatible':
        try:
            base = validate_custom_base(custom_base)
        except ValueError:
            raise DiscoveryError('unsupported') from None
    else:
        base = DISCOVERY_BASES.get(provider_type) or PROVIDERS[provider_type]['base']
    if not base:
        raise DiscoveryError('unsupported')
    headers = {'Authorization': 'Bearer ' + secret, 'Accept': 'application/json'}
    if provider_type == 'anthropic':
        headers = {'x-api-key': secret, 'anthropic-version': '2023-06-01', 'Accept':'application/json'}
    elif provider_type == 'gemini':
        headers = {'x-goog-api-key': secret, 'Accept':'application/json'}
    try:
        models, seen, cursors = [], set(), set()
        params, partial = {}, False
        async with asyncio.timeout(min(UPSTREAM_TIMEOUT_SECONDS, 30)):
            async with httpx.AsyncClient(timeout=min(UPSTREAM_TIMEOUT_SECONDS, 30), follow_redirects=False, trust_env=False) as client:
                for page in range(10):
                    async with client.stream('GET', base.rstrip('/') + '/models', headers=headers, params=params) as response:
                        if response.status_code in (401, 403):
                            raise DiscoveryError('authentication')
                        if response.status_code == 404:
                            raise DiscoveryError('unsupported')
                        if response.status_code == 429:
                            raise DiscoveryError('rate_limited')
                        if response.status_code != 200:
                            raise DiscoveryError('unavailable')
                        chunks, size = [], 0
                        async for chunk in response.aiter_bytes():
                            size += len(chunk)
                            if size > 2 * 1024 * 1024:
                                raise DiscoveryError('invalid_response')
                            chunks.append(chunk)
                    try:
                        payload = json.loads(b''.join(chunks))
                    except (ValueError, UnicodeError, RecursionError):
                        raise DiscoveryError('invalid_response') from None
                    items = payload.get('models' if provider_type in ('typesafe', 'gemini') else 'data') if isinstance(payload, dict) else None
                    if not isinstance(items, list):
                        raise DiscoveryError('invalid_response')
                    for item in items:
                        if len(models) >= 1000:
                            partial = True
                            break
                        if not isinstance(item, dict):
                            continue
                        name = item.get('name' if provider_type in ('typesafe', 'gemini') else 'id')
                        if provider_type == 'gemini' and isinstance(name, str):
                            name = name.removeprefix('models/')
                        if not isinstance(name, str) or not name or len(name) > 200 or name in seen:
                            continue
                        seen.add(name)
                        label = item.get('displayName') if provider_type == 'gemini' else item.get('name')
                        models.append({'id': name, 'name': label[:200] if isinstance(label, str) else name})
                    more = bool(payload.get('has_more') or payload.get('nextPageToken'))
                    if partial or not more:
                        break
                    if provider_type == 'gemini':
                        cursor, key = payload.get('nextPageToken'), 'pageToken'
                    elif provider_type in ('openai', 'anthropic'):
                        cursor, key = payload.get('last_id'), 'after' if provider_type == 'openai' else 'after_id'
                    else:
                        partial = True
                        break
                    if not isinstance(cursor, str) or not cursor or len(cursor) > 512 or cursor in cursors:
                        partial = True
                        break
                    cursors.add(cursor)
                    params = {key: cursor}
                    if page == 9:
                        partial = True
        return {'models': models, 'partial': partial}

    except DiscoveryError:
        raise
    except (TimeoutError, httpx.TimeoutException):
        raise DiscoveryError('timeout') from None
    except (httpx.HTTPError, ValueError, TypeError):
        raise DiscoveryError('unavailable') from None


def validate_custom_base(base: str | None) -> str:
    allowed = {item.strip().rstrip('/') for item in os.environ.get('MAGPIE_ALLOWED_PROVIDER_BASES', '').split(',') if item.strip()}
    if not base or base.rstrip('/') not in allowed:
        raise ValueError('Provider base is not in the configured allowlist')
    parsed = urlsplit(base)
    if parsed.scheme != 'https' or not parsed.hostname or parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise ValueError('Provider base must be an HTTPS URL without credentials, query or fragment')
    if parsed.hostname.lower() in ('localhost', 'localhost.localdomain'):
        raise ValueError('Local provider base is not permitted')
    try:
        address = ipaddress.ip_address(parsed.hostname)
    except ValueError:
        address = None
    if address is not None and not address.is_global:
        raise ValueError('Private provider IP is not permitted')
    return base.rstrip('/')


def provider_arguments(provider_type: str, model: str, secret: str, custom_base: str | None = None) -> dict:
    config = PROVIDERS[provider_type]
    args = {"model": f"{config['prefix']}/{model}", "api_key": secret, "timeout": UPSTREAM_TIMEOUT_SECONDS, "num_retries": 0}
    base = validate_custom_base(custom_base) if provider_type == "openai_compatible" else config["base"]
    if base:
        args["api_base"] = base
    return args


async def completion(config: dict, data: dict):
    config = dict(config)
    reported_usage = None
    reported_error = False
    if config['model'].startswith('openai/') and not data.get('stream'):
        def capture_usage(details):
            nonlocal reported_usage, reported_error
            if not isinstance(details, dict) or details.get('log_event_type') != 'post_api_call':
                return
            reported_usage = None
            try:
                response = details.get('original_response')
                response = json.loads(response) if isinstance(response, str) else response
                if isinstance(response, dict) and response.get('error') is not None:
                    reported_error = True
                usage = response.get('usage') if isinstance(response, dict) else None
                reported_usage = reported_token_counts(usage)
            except (TypeError, ValueError):
                pass  # Missing or changed LiteLLM internals fall back to conservative accounting.
        config['logger_fn'] = capture_usage
    result = await litellm.acompletion(**config, **data)
    if reported_error:
        raise ProviderStatusError(502)
    hidden = getattr(result, '_hidden_params', None)
    if reported_usage is not None and isinstance(hidden, dict):
        hidden['magpie_reported_usage'] = reported_usage
    if data.get('stream') and config['model'].startswith('gemini/'):
        try:
            return GeminiTerminalStream(result)
        except Exception:
            close = getattr(result, 'aclose', None)
            if close:
                await close()
            raise
    if data.get('stream') and config['model'].startswith('openai/'):
        source = getattr(result, 'completion_stream', None)
        return OpenAIStreamProvenance(result, source if isinstance(source, AsyncStream) else None, require_native_done=True)
    if data.get('stream') and config['model'].startswith('anthropic/'):
        return AnthropicStreamProvenance(result)
    if data.get('stream') and config['model'].startswith('groq/'):
        return NativeSSEUsageStream(result, 'groq', bool((data.get('stream_options') or {}).get('include_usage')))
    if data.get('stream') and config['model'].split('/', 1)[0] in ('openrouter', 'deepseek', 'xai', 'mistral', 'together_ai', 'fireworks_ai'):
        return NativeSSEUsageStream(result, config['model'].split('/', 1)[0], bool((data.get('stream_options') or {}).get('include_usage')))
    if data.get('stream'):
        source = getattr(result, 'completion_stream', None)
        # Other LiteLLM adapters may synthesize usage, too. Only an actual
        # OpenAI SDK stream exposes pre-normalization SDK chunks here.
        return OpenAIStreamProvenance(result, source if isinstance(source, AsyncStream) else None, require_native_done=isinstance(source, AsyncStream))
    return result


def reported_token_counts(usage):
    """Keep only explicit, valid standard token counts from a provider event."""
    if not isinstance(usage, dict):
        return None
    counts = {name: usage[name] for name in ('prompt_tokens', 'completion_tokens', 'total_tokens') if name in usage}
    if counts and all(type(value) is int and 0 <= value <= 2147483647 for value in counts.values()):
        return counts
    return None


def gemini_reported_usage(metadata):
    """Use only native counts whose billing dimensions are unambiguous."""
    if not isinstance(metadata, dict):
        return None
    fields = ('promptTokenCount', 'candidatesTokenCount', 'totalTokenCount',
              'cachedContentTokenCount', 'toolUsePromptTokenCount', 'thoughtsTokenCount')
    if any(type(metadata[name]) is not int or not 0 <= metadata[name] <= 2147483647
           for name in fields if name in metadata):
        return None
    counts = {}
    if 'promptTokenCount' in metadata and not metadata.get('cachedContentTokenCount', 0) and not metadata.get('toolUsePromptTokenCount', 0):
        counts['prompt_tokens'] = metadata['promptTokenCount']
    if 'candidatesTokenCount' in metadata and not metadata.get('thoughtsTokenCount', 0):
        counts['completion_tokens'] = metadata['candidatesTokenCount']
    if len(counts) == 2 and 'totalTokenCount' in metadata:
        counts['total_tokens'] = metadata['totalTokenCount']
    return counts or None


class OpenAIStreamProvenance:
    """Observe SDK chunks before LiteLLM can default missing usage to zero."""
    def __init__(self, stream, source, require_native_done=False):
        self.stream = stream
        self.magpie_usage_tracking = True
        self.magpie_reported_usage = None
        self._require_native_done = require_native_done
        self._native_done = False
        self._source = source
        self._source_closed = False
        if source is None:
            return  # An unknown SDK interface must never make synthetic usage billable.

        native_events = getattr(source, '_iter_events', None)
        if require_native_done and callable(native_events):
            async def observe_events():
                async for event in native_events():
                    if getattr(event, 'data', None) == '[DONE]':
                        self._native_done = True
                    yield event
            source._iter_events = observe_events

        async def observe():
            try:
                async for chunk in source:
                    if hasattr(chunk, 'model_dump'):
                        raw = chunk.model_dump(exclude_unset=True)
                        if isinstance(raw, dict) and raw.get('usage') is not None:
                            self.magpie_reported_usage = reported_token_counts(raw['usage'])
                    yield chunk
            finally:
                await self._close_source()

        stream.completion_stream = observe()

    def __aiter__(self):
        return self

    async def __anext__(self):
        try:
            return await anext(self.stream)
        except StopAsyncIteration:
            if self._require_native_done and not self._native_done:
                raise ValueError('Provider stream lacks native completion') from None
            raise

    async def aclose(self):
        close = getattr(self.stream, 'aclose', None)
        try:
            if close:
                await close()
        finally:
            await self._close_source()

    async def _close_source(self):
        if self._source_closed or self._source is None:
            return
        self._source_closed = True
        close = getattr(self._source, 'aclose', None) or getattr(self._source, 'close', None)
        if close:
            result = close()
            if inspect.isawaitable(result):
                await result


class NativeSSEUsageStream:
    """Capture selected providers' native usage before LiteLLM conversion."""
    def __init__(self, stream, provider, include_usage):
        from litellm.llms.openai_like.chat.handler import ModelResponseIterator
        from litellm.llms.groq.chat.transformation import GroqChatCompletionStreamingHandler
        from litellm.llms.openrouter.chat.transformation import OpenRouterChatCompletionStreamingHandler
        from litellm.llms.openai.chat.gpt_transformation import OpenAIChatCompletionStreamingHandler
        from litellm.llms.xai.chat.transformation import XAIChatCompletionStreamingHandler
        from litellm.llms.mistral.chat.transformation import MistralChatResponseIterator
        from litellm.llms.fireworks_ai.chat.transformation import FireworksAIChatCompletionStreamingHandler
        self.stream = stream
        self.provider = provider
        self.include_usage = include_usage
        self.magpie_usage_tracking = True
        self.magpie_reported_usage = None
        self._client_usage = None
        self._native_done = False
        inner = getattr(stream, 'completion_stream', None)
        source = getattr(inner, 'streaming_response', None)
        expected = {'groq': (ModelResponseIterator, GroqChatCompletionStreamingHandler),
                    'openrouter': (OpenRouterChatCompletionStreamingHandler,),
                    'deepseek': (OpenAIChatCompletionStreamingHandler,),
                    'xai': (XAIChatCompletionStreamingHandler,),
                    'mistral': (MistralChatResponseIterator,),
                    'together_ai': (OpenAIChatCompletionStreamingHandler,),
                    'fireworks_ai': (FireworksAIChatCompletionStreamingHandler,)}
        if not isinstance(inner, expected[provider]) or source is None or not hasattr(source, '__aiter__'):
            return

        async def observe():
            try:
                async for line in source:
                    self._observe_line(line)
                    yield line
            finally:
                close = getattr(source, 'aclose', None)
                if close:
                    await close()
        inner.streaming_response = observe()

    def _observe_line(self, line):
        if not isinstance(line, str) or not line.startswith('data:'):
            return
        if line[5:].strip() == '[DONE]':
            self._native_done = True
            return
        try:
            event = json.loads(line[5:].strip())
        except (TypeError, ValueError):
            return
        if not isinstance(event, dict):
            return
        if event.get('error') is not None:
            raise ValueError('Provider stream reported an error')
        if self.provider == 'groq':
            extension = event.get('x_groq')
            raw = extension.get('usage') if isinstance(extension, dict) else None
        else:
            raw = event.get('usage')
        if raw is not None:
            self.magpie_reported_usage = reported_token_counts(raw)

    def __aiter__(self):
        return self

    async def __anext__(self):
        try:
            chunk = await anext(self.stream)
        except StopAsyncIteration:
            if not self._native_done:
                raise ValueError('Provider stream lacks native completion') from None
            raise
        if self.include_usage and self.magpie_reported_usage is not None and self.magpie_reported_usage != self._client_usage:
            data = as_dict(chunk)
            if isinstance(data, dict):
                data['usage'] = dict(self.magpie_reported_usage)
                self._client_usage = dict(self.magpie_reported_usage)
                return data
        return chunk

    async def aclose(self):
        close = getattr(self.stream, 'aclose', None)
        if close:
            await close()


class AnthropicStreamProvenance:
    """Observe native token counts and the message-stop terminal event."""
    def __init__(self, stream):
        self.stream = stream
        self.magpie_usage_tracking = True
        self.magpie_reported_usage = None
        self._native_stop = False
        self._observed_source = None
        self._input_ambiguous = False
        inner = getattr(stream, 'completion_stream', None)
        source = getattr(inner, 'streaming_response', None)
        if source is None or not hasattr(source, '__aiter__'):
            return

        async def observe():
            try:
                async for line in source:
                    self._observe_line(line)
                    yield line
            finally:
                close = getattr(source, 'aclose', None)
                if close:
                    await close()
        self._observed_source = observe()
        inner.streaming_response = self._observed_source

    def _observe_line(self, line):
        if not isinstance(line, str) or not line.startswith('data:'):
            return
        try:
            event = json.loads(line[5:].strip())
        except (TypeError, ValueError):
            return
        if not isinstance(event, dict):
            return
        if event.get('type') == 'error' or event.get('error') is not None:
            raise ValueError('Provider stream reported an error')
        if event.get('type') == 'message_stop':
            self._native_stop = True
            return
        if event.get('type') == 'message_start':
            message = event.get('message')
            usage = message.get('usage') if isinstance(message, dict) else None
            self.magpie_reported_usage = None
            self._input_ambiguous = False
            if isinstance(usage, dict):
                counts = reported_token_counts({'prompt_tokens': usage.get('input_tokens')})
                cache = [usage.get('cache_read_input_tokens', 0), usage.get('cache_creation_input_tokens', 0)]
                self._input_ambiguous = not all(type(v) is int and v == 0 for v in cache)
                if counts and not self._input_ambiguous:
                    self.magpie_reported_usage = counts
        elif event.get('type') == 'message_delta':
            usage = event.get('usage')
            existing = dict(self.magpie_reported_usage or {})
            if isinstance(usage, dict):
                if 'input_tokens' in usage:
                    existing.pop('prompt_tokens', None)
                    counts = reported_token_counts({'prompt_tokens': usage['input_tokens']})
                    if counts and not self._input_ambiguous:
                        existing.update(counts)
                if any(type(usage[name]) is not int or usage[name] != 0
                       for name in ('cache_read_input_tokens', 'cache_creation_input_tokens') if name in usage):
                    self._input_ambiguous = True
                    existing.pop('prompt_tokens', None)
                if 'output_tokens' in usage:
                    existing.pop('completion_tokens', None)
                    counts = reported_token_counts({'completion_tokens': usage['output_tokens']})
                    if counts:
                        existing.update(counts)
            self.magpie_reported_usage = existing or None

    def __aiter__(self):
        return self

    async def __anext__(self):
        try:
            return await anext(self.stream)
        except StopAsyncIteration:
            if not self._native_stop and self._observed_source is not None:
                async for _ in self._observed_source:
                    if self._native_stop:
                        break
            if not self._native_stop:
                raise ValueError('Provider stream lacks native completion') from None
            raise

    async def aclose(self):
        close = getattr(self.stream, 'aclose', None)
        try:
            if close:
                await close()
        finally:
            if self._observed_source is not None:
                await self._observed_source.aclose()


class GeminiTerminalStream:
    """Track Gemini's native SSE finish signal before LiteLLM can synthesize one.

    LiteLLM 1.109.1 exposes a per-stream lazy `make_call` and raw line iterator.
    Fail closed if this interface changes, rather than claiming completion.
    """
    def __init__(self, stream):
        self.stream = stream
        self.seen, self.finished = set(), set()
        self.blocked = False
        self.magpie_usage_tracking = True
        self.magpie_reported_usage = None
        make_call = getattr(stream, 'make_call', None)
        if not callable(make_call):
            raise ValueError('Gemini stream cannot verify native completion')

        async def observed_call(*args, **kwargs):
            inner = await make_call(*args, **kwargs)
            source = getattr(inner, 'streaming_response', None)
            if source is None or not hasattr(source, '__aiter__'):
                raise ValueError('Gemini stream cannot verify native completion')

            async def observe():
                try:
                    async for line in source:
                        self._observe_line(line)
                        yield line
                finally:
                    close = getattr(source, 'aclose', None)
                    if close:
                        await close()
            inner.streaming_response = observe()
            return inner

        stream.make_call = observed_call

    def _observe_line(self, line):
        if isinstance(line, str) and line.startswith('data:'):
            try:
                event = json.loads(line[5:].strip())
            except (ValueError, TypeError):
                event = None
            if isinstance(event, dict):
                if 'usageMetadata' in event:
                    self.magpie_reported_usage = gemini_reported_usage(event['usageMetadata'])
                feedback = event.get('promptFeedback')
                if isinstance(feedback, dict) and isinstance(feedback.get('blockReason'), str) and feedback['blockReason']:
                    self.blocked = True
                candidates = event.get('candidates')
                if isinstance(candidates, list):
                    for index, candidate in enumerate(candidates):
                        if not isinstance(candidate, dict):
                            continue
                        candidate_index = candidate.get('index', index)
                        if type(candidate_index) is not int or candidate_index < 0:
                            continue
                        self.seen.add(candidate_index)
                        reason = candidate.get('finishReason')
                        if isinstance(reason, str) and reason:
                            self.finished.add(candidate_index)

    def __aiter__(self):
        return self

    async def __anext__(self):
        chunk = await anext(self.stream)
        data = as_dict(chunk)
        choices = data.get('choices', []) if isinstance(data, dict) else []
        if any(isinstance(choice, dict) and choice.get('finish_reason') for choice in choices):
            if not ((not self.seen and self.blocked) or (self.seen and self.seen == self.finished)):
                raise ValueError('Gemini stream lacks native completion')
        return chunk

    async def aclose(self):
        close = getattr(self.stream, 'aclose', None)
        if close:
            await close()


async def decision(config: dict, data: dict):
    # LiteLLM's decisions handler does not expose its per-request HTTP client
    # or post-call logging. Observe the original response using a proxy on the
    # request-local provider configuration, before LiteLLM fills missing usage.
    from litellm.decisions.main import _prepare_decisions_call, asend
    args = dict(config, **data)
    fields = {name: args.pop(name, None) for name in
              ('model', 'input', 'questions', 'safety_identifier', 'audio', 'videos',
               'api_key', 'api_base', 'timeout', 'custom_llm_provider', 'extra_headers')}
    call = await asyncio.to_thread(partial(_prepare_decisions_call,
        model=fields['model'], decision_input=fields['input'], questions=fields['questions'],
        safety_identifier=fields['safety_identifier'], audio=fields['audio'], videos=fields['videos'],
        api_key=fields['api_key'], api_base=fields['api_base'], timeout=fields['timeout'],
        custom_llm_provider=fields['custom_llm_provider'], extra_headers=fields['extra_headers'], kwargs=args))
    observer = DecisionConfigObserver(call.provider_config)
    result = await asend(replace(call, provider_config=observer))
    return DecisionProvenance(result, observer.reported)


class DecisionConfigObserver:
    """Capture counts only, with no global hooks or retained response data."""
    def __init__(self, delegate):
        self.delegate = delegate
        self.reported = None

    def __getattr__(self, name):
        return getattr(self.delegate, name)

    def transform_decisions_response(self, *args, **kwargs):
        response = kwargs.get('raw_response')
        if response is None or type(response.status_code) is not int or response.status_code != 200:
            raise ProviderStatusError(response.status_code if response is not None and type(response.status_code) is int else 502)
        try:
            payload = response.json()
        except (AttributeError, ValueError, TypeError):
            payload = None  # Let the provider's response validator reject malformed JSON.
        if isinstance(payload, dict) and payload.get('error') is not None:
            raise ProviderStatusError(502)
        result = self.delegate.transform_decisions_response(*args, **kwargs)
        usage = payload.get('usage') if isinstance(payload, dict) else None
        self.reported = reported_decision_counts(usage)
        return result


def reported_decision_counts(usage):
    if not isinstance(usage, dict):
        return None
    counts = {}
    for name, detail_name, extras, top_level in (
        ('input_tokens', 'input_tokens_details', ('cached_tokens', 'cache_write_tokens'),
         ('cached_tokens', 'cache_write_tokens', 'cache_read_input_tokens', 'cache_creation_input_tokens')),
        ('output_tokens', 'output_tokens_details', ('reasoning_tokens',), ('reasoning_tokens',)),
    ):
        value = usage.get(name)
        detail = usage.get(detail_name, {})
        if (type(value) is int and 0 <= value <= 2147483647 and isinstance(detail, dict)
                and all(type(detail.get(key, 0)) is int and detail.get(key, 0) == 0 for key in extras)
                and all(type(usage.get(key, 0)) is int and usage.get(key, 0) == 0 for key in top_level)):
            counts[name] = value
    total = usage.get('total_tokens')
    if (len(counts) == 2 and type(total) is int and 0 <= total <= 2147483647
            and total == sum(counts.values())):
        counts['total_tokens'] = total
    return counts or None


class DecisionProvenance:
    def __init__(self, result, reported):
        self.result = result
        self.reported = reported

    def model_dump(self, **kwargs):
        return self.result.model_dump(**kwargs) if hasattr(self.result, 'model_dump') else self.result


def apply_decision_usage(data, result):
    if isinstance(result, DecisionProvenance):
        if result.reported is not None:
            data['usage'] = dict(result.reported)
        else:
            data.pop('usage', None)
    else:
        normalize_decision_usage(data)


class ScopedEmbeddingLogging(Logging):
    def __init__(self, capture, **kwargs):
        self._magpie_capture = capture
        super().__init__(**kwargs)

    def update_environment_variables(self, *args, **kwargs):
        kwargs['litellm_params'] = dict(kwargs.get('litellm_params') or {}, logger_fn=self._magpie_capture)
        return super().update_environment_variables(*args, **kwargs)


async def embedding(config: dict, data: dict):
    config = dict(config)
    if config['model'].startswith('gemini/'):
        from litellm.llms.vertex_ai.gemini_embeddings import batch_embed_content_handler
        delegate = config.get('client') or batch_embed_content_handler.get_async_httpx_client(
            llm_provider=litellm.LlmProviders.VERTEX_AI, params={'timeout':config.get('timeout')})
        observer = GeminiEmbeddingHTTP(delegate)
        # LiteLLM's Gemini batch_embeddings currently drops its client when
        # entering the async path. Scope the forwarding fix to this call.
        class ScopedGeminiBatch(batch_embed_content_handler.GoogleBatchEmbeddings):
            async def async_batch_embeddings(self, *args, **kwargs):
                kwargs['client'] = observer
                return await super().async_batch_embeddings(*args, **kwargs)
        model = config['model'].removeprefix('gemini/')
        optional = litellm.utils.get_optional_params_embeddings(model=model, custom_llm_provider='gemini',
            dimensions=data.get('dimensions'))
        result = await ScopedGeminiBatch().batch_embeddings(model=model, input=data['input'], print_verbose=lambda *args: None,
            model_response=litellm.EmbeddingResponse(), custom_llm_provider='gemini', optional_params=optional,
            logging_obj=None, api_key=config.get('api_key'), api_base=config.get('api_base'),
            aembedding=True, timeout=config.get('timeout'), client=observer)
        return EmbeddingProvenance(result, observer.reported)
    if not config['model'].startswith('openai/'):
        return await litellm.aembedding(**config, **data)

    # In LiteLLM 1.109.1 the embedding entry point drops logger_fn before it
    # configures its per-request logger. Supply an isolated logger that adds
    # only our callback back; never mutate global callbacks or retain content.
    reported = None
    reported_error = False
    def capture(details):
        nonlocal reported, reported_error
        if not isinstance(details, dict) or details.get('log_event_type') != 'post_api_call':
            return
        reported = None
        try:
            response = details.get('original_response')
            response = json.loads(response) if isinstance(response, str) else response
            if isinstance(response, dict) and response.get('error') is not None:
                reported_error = True
            usage = response.get('usage') if isinstance(response, dict) else None
            if not isinstance(usage, dict):
                return
            prompt, total = usage.get('prompt_tokens'), usage.get('total_tokens')
            details = usage.get('prompt_tokens_details')
            if details is not None and not isinstance(details, dict):
                return
            cache = [usage.get('cache_read_input_tokens', 0), usage.get('cache_creation_input_tokens', 0),
                     (details or {}).get('cached_tokens', 0)]
            if any(type(value) is not int or value != 0 for value in cache):
                return
            if type(prompt) is not int or not 0 <= prompt <= 2147483647:
                return
            if total is not None and (type(total) is not int or not prompt <= total <= 2147483647):
                return
            reported = {'prompt_tokens': prompt}
            if total is not None:
                reported['total_tokens'] = total
        except (TypeError, ValueError):
            pass
    call_id = str(uuid.uuid4())
    config['litellm_logging_obj'] = ScopedEmbeddingLogging(capture, model=config['model'], messages=data.get('input'),
        stream=False, call_type='aembedding', start_time=datetime.now(), litellm_call_id=call_id, function_id=call_id)
    result = await litellm.aembedding(**config, **data)
    if reported_error:
        raise ProviderStatusError(502)
    return EmbeddingProvenance(result, reported)


class EmbeddingProvenance:
    """Keep request-local provenance even if LiteLLM's hidden fields change."""
    def __init__(self, result, reported):
        self.result = result
        self.reported = reported

    def model_dump(self, **kwargs):
        return self.result.model_dump(**kwargs) if hasattr(self.result, 'model_dump') else self.result


class GeminiEmbeddingHTTP:
    """Observe Gemini batch usage without retaining input, vectors, or keys."""
    def __init__(self, delegate):
        self.delegate = delegate
        self.reported = None

    def __getattr__(self, name):
        return getattr(self.delegate, name)

    async def post(self, *args, **kwargs):
        try:
            response = await self.delegate.post(*args, **kwargs)
        except httpx.TimeoutException:
            raise TimeoutError('Provider request timed out') from None
        except httpx.HTTPStatusError as exc:
            raise ProviderStatusError(exc.response.status_code) from None
        url = kwargs.get('url', args[0] if args else '')
        if isinstance(url, str) and url.split('?', 1)[0].endswith(':batchEmbedContents'):
            if response.status_code != 200:
                raise ProviderStatusError(response.status_code)
            self.reported = None
            try:
                body = response.json() if response.status_code == 200 else None
                if isinstance(body, dict) and body.get('error') is not None:
                    raise ProviderStatusError(502)
                usage = body.get('usageMetadata') if isinstance(body, dict) else None
                if isinstance(usage, dict):
                    prompt = usage.get('promptTokenCount')
                    cache = [usage.get('cachedContentTokenCount', 0), usage.get('toolUsePromptTokenCount', 0)]
                    if type(prompt) is int and 0 <= prompt <= 2147483647 and all(type(v) is int and v == 0 for v in cache):
                        self.reported = {'prompt_tokens':prompt}
            except (TypeError, ValueError):
                pass
        return response


class ProviderStatusError(Exception):
    def __init__(self, status_code):
        super().__init__('Provider request failed')
        self.status_code = status_code


def as_dict(value):
    return value.model_dump(exclude_none=True) if hasattr(value, "model_dump") else value


def normalize_decision_usage(data: dict) -> None:
    """LiteLLM can default missing decision token dimensions to zero.

    The normalized response has lost provenance, so a zero cannot safely be
    distinguished from a missing field. Positive values remain usable.
    """
    usage = data.get('usage')
    if not isinstance(usage, dict):
        data.pop('usage', None)
        return
    known = []
    for names, details in ((('input_tokens', 'prompt_tokens'), ('input_tokens_details', 'prompt_tokens_details')),
                           (('output_tokens', 'completion_tokens'), ('output_tokens_details', 'completion_tokens_details'))):
        value = next((usage[name] for name in names if name in usage), None)
        present = type(value) is int and value > 0
        known.append(present)
        if not present:
            for name in names:
                usage.pop(name, None)
            for name in details:
                usage.pop(name, None)
    if not all(known):
        usage.pop('total_tokens', None)
    if not any(known):
        data.pop('usage', None)


def normalize_generation_usage(data: dict, provider_type: str) -> None:
    """Do not treat adapter-defaulted counts as provider-reported usage.

    Adapters can default missing dimensions to zero. Cache and reasoning
    counts can also make a missing base dimension appear positive.
    """
    normalize_decision_usage(data)
    usage = data.get('usage')
    if not isinstance(usage, dict):
        return
    details = usage.get('prompt_tokens_details')
    details = details if isinstance(details, dict) else {}
    cache_fields = [usage.get('cache_read_input_tokens'), usage.get('cache_creation_input_tokens'),
                    details.get('cached_tokens'), details.get('tool_use_tokens')]
    ambiguous_input = any(type(value) is int and value > 0 for value in cache_fields)
    output_details = usage.get('completion_tokens_details')
    output_details = output_details if isinstance(output_details, dict) else {}
    ambiguous_output = any(
        type(value) is int and value > 0 for value in (usage.get('reasoning_tokens'), output_details.get('reasoning_tokens')))
    for ambiguous, names in ((ambiguous_input, ('prompt_tokens', 'input_tokens', 'prompt_tokens_details')),
                             (ambiguous_output, ('completion_tokens', 'output_tokens', 'completion_tokens_details'))):
        if ambiguous:
            for name in names:
                usage.pop(name, None)
            usage.pop('total_tokens', None)
    if not any(name in usage for name in ('prompt_tokens', 'input_tokens', 'completion_tokens', 'output_tokens')):
        data.pop('usage', None)


def apply_generation_usage(data: dict, result, provider_type: str) -> None:
    """Prefer explicitly reported provider counts when available."""
    hidden = getattr(result, '_hidden_params', None)
    counts = hidden.get('magpie_reported_usage') if isinstance(hidden, dict) else getattr(result, 'magpie_reported_usage', None)
    if isinstance(counts, dict):
        usage = data.get('usage')
        usage = dict(usage) if isinstance(usage, dict) else {}
        for name in ('prompt_tokens', 'input_tokens', 'completion_tokens', 'output_tokens', 'total_tokens'):
            usage.pop(name, None)
        if provider_type in ('gemini', 'anthropic'):
            for name in ('prompt_tokens_details', 'input_tokens_details', 'completion_tokens_details', 'output_tokens_details'):
                usage.pop(name, None)
        if 'prompt_tokens' not in counts:
            usage.pop('prompt_tokens_details', None)
            usage.pop('input_tokens_details', None)
        if 'completion_tokens' not in counts:
            usage.pop('completion_tokens_details', None)
            usage.pop('output_tokens_details', None)
        usage.update(counts)
        data['usage'] = usage
    else:
        normalize_generation_usage(data, provider_type)


def normalize_embedding_usage(data: dict) -> None:
    """Embedding adapters can synthesize zero usage when the provider omits it."""
    usage = data.get('usage')
    if not isinstance(usage, dict):
        data.pop('usage', None)
        return
    value = next((usage[name] for name in ('prompt_tokens', 'input_tokens') if name in usage), None)
    details = usage.get('prompt_tokens_details')
    details = details if isinstance(details, dict) else {}
    if (type(value) is not int or value <= 0 or
            any(type(v) is int and v > 0 for v in (usage.get('cache_read_input_tokens'),
                usage.get('cache_creation_input_tokens'), details.get('cached_tokens')))):
        data.pop('usage', None)
        return
    for name in ('completion_tokens', 'output_tokens', 'completion_tokens_details', 'output_tokens_details'):
        usage.pop(name, None)
    if usage.get('total_tokens') == 0:
        usage.pop('total_tokens', None)


def apply_embedding_usage(data: dict, result) -> None:
    if isinstance(result, EmbeddingProvenance):
        counts = result.reported
        if isinstance(counts, dict):
            data['usage'] = dict(counts)
        else:
            data.pop('usage', None)
    else:
        normalize_embedding_usage(data)
