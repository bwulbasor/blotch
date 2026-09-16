# blotch local gateway daemon.
#
# The image runs `blotch serve` (plan §13). Detection, the vault, and all
# sensitive data stay inside the container/host - nothing is sent anywhere.
#
#   docker build -t blotch .
#   docker run --rm -p 8723:8723 blotch
#   # then open http://127.0.0.1:8723/  (web UI) or POST the JSON endpoints
#
# The default extras include crypto (encrypted vaults) + docs (PDF/DOCX); the
# core needs no third-party deps. spaCy is intentionally left out (large);
# add it yourself if you want model-based NER.
FROM python:3.12-slim

WORKDIR /app
COPY pyproject.toml README.md ./
COPY src ./src
RUN pip install --no-cache-dir ".[crypto,docs]"

# Serve on all interfaces *inside the container*; publish only to loopback on the
# host (`-p 127.0.0.1:8723:8723`) - the daemon returns vault material in
# responses and must not be exposed to an untrusted network.
EXPOSE 8723
ENTRYPOINT ["blotch", "serve", "--host", "0.0.0.0", "--port", "8723"]
