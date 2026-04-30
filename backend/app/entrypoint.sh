#!/bin/sh
set -e

# Создаёт пустой файл, если его нет
mkdir -p /app
: > /app/traffic.db || true

mkdir -p /app/files

exec "$@"