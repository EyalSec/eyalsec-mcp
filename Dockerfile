# Runs the EyalSec MCP server on stdio:
#   docker build -t eyalsec-mcp .
#   docker run --rm -i -e EYALSEC_API_KEY=es2_your_read_only_key eyalsec-mcp
FROM python:3.14-slim@sha256:a2b82f3c48559aa0a8446d9af49826b6e2b2016f4cd2afabfe6013ec53729170
WORKDIR /app
COPY pyproject.toml README.md LICENSE ./
COPY src ./src
RUN pip install --no-cache-dir . && useradd --create-home mcp
USER mcp
ENTRYPOINT ["eyalsec-mcp"]
