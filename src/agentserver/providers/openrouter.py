"""OpenRouter client, via the OpenAI SDK. M3.

OpenRouter is OpenAI-compatible and ships no SDK of its own:

    OpenAI(base_url="https://openrouter.ai/api/v1",
           api_key=os.environ["OPENROUTER_API_KEY"])

The model is a `vendor/model` slug from `config/governor.yaml`, never
hardcoded. Swapping the model must not require a code change — and because it
is configuration, the evaluations can sweep it, which turns "does containment
hold with a weaker or stronger planner" into a config loop rather than a
rewrite.

**Structured output is best-effort here.** Support varies by model *and* by the
provider OpenRouter routes to, so non-conforming output is a normal case rather
than an exceptional one. It lands as a schema rejection, is logged, and costs
the caller a turn.

**Model output is never repaired to make it parse.** Silently fixing it up is
how an injected instruction gets laundered into a valid-looking action. A
malformed response is a refusal, not something to coax into shape.

One property worth keeping in mind: routing an untrusted component through a
third party we do not control changes nothing about the security model. The
governor and subagents were already untrusted; that the architecture is
indifferent to where they run is the design holding, not a concession.

TODO(M3): client construction, chat(), structured output via response_format,
          timeout and retry under caller control, attribution headers,
          usage accounting for the cost figures in the writeup
"""
