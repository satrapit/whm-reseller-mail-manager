# Isolated mock WHM runner: no network at runtime and no production mounts.
FROM python:3.11-slim-bookworm
RUN apt-get update \
 && apt-get install -y --no-install-recommends util-linux \
 && rm -rf /var/lib/apt/lists/*
RUN command -v bash && command -v flock && command -v cp && command -v stat
WORKDIR /source
ENTRYPOINT ["bash", "/source/tests/lifecycle/run.sh"]
