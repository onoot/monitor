# The checker container: the real AltayCTF checkers, run from inside the stand.
#
# It is what a grader is on the real network: a machine outside the team range
# that dials the gateway, registers users, puts new flags and retrieves the old
# ones. Its source address (10.78.0.250 on checker-net) is listed as `checker` in
# gateway.json, so its traffic lands in the dashboard's "Чекер" tab and is never
# policed.
#
# The checkers and their compatible framework live in the repository, so the
# image is built from the same code under review rather than a copy that drifts.

FROM python:3.12-slim

WORKDIR /app

# aiohttp drives the checks, faker feeds the checkers their synthetic usernames.
RUN pip install --no-cache-dir aiohttp faker

COPY checkers ./checkers
COPY pylibs ./pylibs
COPY tools ./tools
COPY services/monitoring/checker/entrypoint.sh ./entrypoint.sh

ENV PYTHONPATH=/app
ENV PYTHONUNBUFFERED=1

ENTRYPOINT ["sh", "/app/entrypoint.sh"]
