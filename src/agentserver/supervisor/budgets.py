"""Budget enforcement. M2.

Max concurrent subagents, max spawns per task, max wall-clock, max tool calls
per subagent and in total. Kills the runaway/amplification class outright.

TODO(M2): budget tracking, exhaustion -> refuse spawn
"""
