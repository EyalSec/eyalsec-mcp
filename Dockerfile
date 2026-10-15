# Runs the EyalSec MCP server on stdio:
#   docker build -t eyalsec-mcp .
#   docker run --rm -i -e EYALSEC_API_KEY=es2_your_read_only_key eyalsec-mcp
FROM python:3.12-slim
WORKDIR /app
COPY pyproject.toml README.md LICENSE ./
COPY src ./src
RUN pip install --no-cache-dir . && useradd --create-home mcp
USER mcp
ENTRYPOINT ["eyalsec-mcp"]
