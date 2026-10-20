# SHOW discovery image: masscan (fast SYN sweep), arp-scan (L2 local-segment MAC
# discovery), nbtscan (NetBIOS name resolution). All three are Debian packages, so
# one small pinnable image beats hunting fragile single-tool community images.
# Also carries python3 (stdlib only) so scripts/normalize.py can run in-container —
# keeps SHOW's host prerequisites to docker/yq/jq (fully standalone).
FROM debian:12-slim

RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      masscan \
      arp-scan \
      nbtscan \
      iproute2 \
      ca-certificates \
      python3 \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /data

# No ENTRYPOINT: the compose `run` command supplies the tool + args, e.g.
#   docker compose -f docker-compose.show.yml run --rm discovery masscan -p80,443 10.0.0.0/24
#   docker compose -f docker-compose.show.yml run --rm discovery arp-scan --localnet
#   docker compose -f docker-compose.show.yml run --rm discovery nbtscan 10.0.0.0/24
ENTRYPOINT []
