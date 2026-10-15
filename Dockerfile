# Runs the EyalSec MCP server on stdio:
#   docker build -t eyalsec-mcp .
#   docker run --rm -i -e EYALSEC_API_KEY=es2_your_read_only_key eyalsec-mcp
FROM python:3.12-slim@sha256:a6e34c598f2467ed0e9a8d349809fcd8b5c603269512df273a0bb1784edc11b1
WORKDIR /app
COPY pyproject.toml README.md LICENSE ./
COPY src ./src
RUN pip install --no-cache-dir . && useradd --create-home mcp
USER mcp
ENTRYPOINT ["eyalsec-mcp"]
