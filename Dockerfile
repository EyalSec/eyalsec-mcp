# Runs the EyalSec MCP server on stdio:
#   docker build -t eyalsec-mcp .
#   docker run --rm -i -e EYALSEC_API_KEY=es2_your_read_only_key eyalsec-mcp
FROM python:3.12-slim@sha256:5e2bdb1b0d542d5039cffb8181c65930093949194a65c365dfb1b0fe13a4fa5b
WORKDIR /app
COPY pyproject.toml README.md LICENSE ./
COPY src ./src
RUN pip install --no-cache-dir . && useradd --create-home mcp
USER mcp
ENTRYPOINT ["eyalsec-mcp"]
