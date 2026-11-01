#!/bin/sh
mkdir -p "${HOME}/.clipcascade"
exec /usr/bin/python /usr/share/clipcascade/main.py "$@"
