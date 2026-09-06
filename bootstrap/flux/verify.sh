#!/bin/bash
# Retired: use the reviewed controller recovery runbook.
builtin set +x
builtin printf 'BLOCKED Flux live modes are retired; no protected file was read and no cluster request was attempted.\n' >&2
builtin exit 1
