"""Frontier model client. M3. UNTRUSTED side.

OpenRouter, via the OpenAI SDK — OpenRouter is OpenAI-compatible and ships no
SDK of its own:

    from openai import OpenAI
    client = OpenAI(
        base_url="https://openrouter.ai/api/v1",
        api_key=os.environ["OPENROUTER_API_KEY"],
    )

Model is a `vendor/model` slug and lives in config/governor.yaml — never
hardcoded here. Swapping the governor's model must not require a code change;
it is also a variable we may want to sweep in the evals.

The governor has NO tools. It does not tool-call; it emits one structured
object per turn. Request that via response_format json_schema where the routed
model supports it.

IMPORTANT — structured output is best-effort on OpenRouter. Support varies by
model and by the provider actually serving the request, so malformed or
non-conforming output is a NORMAL case here, not an exceptional one. It must
land as a schema rejection in supervisor/contract.py, be logged to the ledger,
and cost the governor a turn. Never repair model output to make it parse:
silently fixing it up is how an injected instruction gets laundered into a
valid-looking action.

The supervisor owns the loop and calls this; nothing here decides anything.
Everything returned is hostile input.

TODO(M3): client init, request with json_schema response_format, retry/timeout
          under supervisor control, attribution headers (HTTP-Referer/X-Title)
"""
