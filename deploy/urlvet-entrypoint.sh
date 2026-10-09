#!/bin/sh
set -eu
CACHE_PASSWORD=$(tr -d '\r\n' < /run/secrets/urlvet_cache_password)
ADMIN_JWT_SECRET=$(tr -d '\r\n' < /run/secrets/urlvet_jwt_secret)
export CACHE_PASSWORD ADMIN_JWT_SECRET
exec /app/urlvet
