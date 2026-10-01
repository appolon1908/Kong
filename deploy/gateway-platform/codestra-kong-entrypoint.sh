#!/bin/sh
set -eu
# Deny before reading credentials or starting any runtime process.
if [ ! -r /etc/codestra/runtime-guard.sh ]; then
  echo "runtime_apply_unauthorized: runtime guard unavailable" >&2
  exit 78
fi
sh /etc/codestra/runtime-guard.sh
# The env Vault provider reads this process variable. It is not a kong.conf
# option, so the upstream Kong entrypoint's generic *_FILE support cannot load it.
sx_redis_file=/run/secrets/redis_password
if [ ! -r "$sx_redis_file" ] || [ ! -s "$sx_redis_file" ]; then
  echo 'Required gateway rate-limit credential is unavailable' >&2
  exit 1
fi
KONG_RATE_LIMIT_REDIS_PASSWORD=$(cat "$sx_redis_file")
export KONG_RATE_LIMIT_REDIS_PASSWORD
sx_oidc_salt_file=/run/secrets/oidc_cache_tokens_salt
if [ ! -r "$sx_oidc_salt_file" ] || [ ! -s "$sx_oidc_salt_file" ]; then
  echo 'Required stable OIDC cache salt is unavailable' >&2
  exit 1
fi
KONG_OIDC_CACHE_TOKENS_SALT=$(cat "$sx_oidc_salt_file")
export KONG_OIDC_CACHE_TOKENS_SALT
sx_webhook_secret_directory=/run/secrets/webhooks
if [ ! -d "$sx_webhook_secret_directory" ] || [ ! -r "$sx_webhook_secret_directory" ] \
    || [ ! -x "$sx_webhook_secret_directory" ]; then
  echo 'Required gateway webhook secret directory is unavailable' >&2
  exit 1
fi
sx_webhook_secret_count=0
for sx_webhook_secret_file in "$sx_webhook_secret_directory"/*; do
  [ -e "$sx_webhook_secret_file" ] || break
  sx_webhook_secret_name=${sx_webhook_secret_file##*/}
  if [ -L "$sx_webhook_secret_file" ] || [ ! -f "$sx_webhook_secret_file" ] \
      || [ ! -r "$sx_webhook_secret_file" ] \
      || ! printf '%s\n' "$sx_webhook_secret_name" | grep -Eq '^kong-webhook-[a-z][a-z0-9-]{1,96}$'; then
    echo 'Invalid gateway webhook secret file' >&2
    exit 1
  fi
  sx_webhook_secret_value=$(cat "$sx_webhook_secret_file")
  case "$sx_webhook_secret_value" in
    *"
"*)
      echo 'Gateway webhook secret must contain exactly one line' >&2
      exit 1
      ;;
  esac
  if [ "${#sx_webhook_secret_value}" -lt 32 ]; then
    echo 'Gateway webhook secret does not meet the minimum length' >&2
    exit 1
  fi
  sx_webhook_secret_environment=$(printf '%s' "$sx_webhook_secret_name" | tr 'a-z-' 'A-Z_')
  export "$sx_webhook_secret_environment=$sx_webhook_secret_value"
  sx_webhook_secret_count=$((sx_webhook_secret_count + 1))
  unset sx_webhook_secret_value sx_webhook_secret_environment
done
if [ "$sx_webhook_secret_count" -eq 0 ]; then
  echo 'At least one gateway webhook secret is required' >&2
  exit 1
fi
exec /docker-entrypoint.sh "$@"
