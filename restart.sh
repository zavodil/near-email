#!/bin/bash
set -e

# near.email mainnet restart script
# Usage:
#   ./restart.sh                    # restart all services
#   ./restart.sh db-api             # restart db-api only
#   ./restart.sh db-api smtp-server # restart specific services
#   ./restart.sh --pull             # git pull + rebuild + restart all
#   ./restart.sh --pull db-api      # git pull + rebuild + restart db-api
#   ./restart.sh --logs db-api      # restart db-api and tail logs

COMPOSE_FILE="docker-compose.yml"
ENV_FILE=".env.mainnet"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

if [ ! -f "$ENV_FILE" ]; then
    echo "ERROR: $ENV_FILE not found in $SCRIPT_DIR"
    exit 1
fi

PULL=false
LOGS=false
SERVICES=()

for arg in "$@"; do
    case "$arg" in
        --pull) PULL=true ;;
        --logs) LOGS=true ;;
        --help|-h)
            echo "Usage: ./restart.sh [--pull] [--logs] [service ...]"
            echo ""
            echo "Options:"
            echo "  --pull    git pull + rebuild before restart"
            echo "  --logs    tail logs after restart"
            echo ""
            echo "Services: db-api, smtp-server, web-ui, postgres"
            echo "No services = restart all"
            exit 0
            ;;
        *) SERVICES+=("$arg") ;;
    esac
done

DC="docker compose -f $COMPOSE_FILE --env-file $ENV_FILE"

if $PULL; then
    echo "==> git pull"
    git pull

    if [ ${#SERVICES[@]} -eq 0 ]; then
        echo "==> rebuild + restart all"
        $DC up -d --build
    else
        echo "==> rebuild + restart: ${SERVICES[*]}"
        $DC up -d --build "${SERVICES[@]}"
    fi
else
    if [ ${#SERVICES[@]} -eq 0 ]; then
        echo "==> restart all"
        $DC up -d --force-recreate
    else
        echo "==> restart: ${SERVICES[*]}"
        $DC up -d --force-recreate "${SERVICES[@]}"
    fi
fi

if $LOGS; then
    if [ ${#SERVICES[@]} -eq 0 ]; then
        $DC logs -f --tail=50
    else
        $DC logs -f --tail=50 "${SERVICES[@]}"
    fi
fi
