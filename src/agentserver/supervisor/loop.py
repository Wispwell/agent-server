"""The governor loop, owned by the supervisor. M2.

Per turn: build state digest -> call governor -> schema-validate output ->
decide -> act -> record. The governor has no callable tools; everything it
knows is injected here.

TODO(M2): run(task), turn(), state digest assembly
"""
