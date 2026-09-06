#!/bin/bash
# Retired: host-token changes require a separately reviewed owner procedure.
builtin set +x
builtin printf 'BLOCKED host-token installer is retired; no token was read and no host change was attempted.\n' >&2
builtin exit 1
