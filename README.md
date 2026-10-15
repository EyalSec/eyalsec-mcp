# EyalSec MCP server

Ask your AI assistant about your EyalSec account in plain words: "what critical events came in since Monday?", "show me the full trace for event 90210", "which machines need an update?". This server gives Claude, Cursor and any other MCP client read access to your events, machines, runs and rules through the [EyalSec API](https://eyalsec.com/docs/api), so the assistant you already use for code review can also help you triage what EyalSec found.

<!-- mcp-name: io.github.EyalSec/eyalsec-mcp -->

EyalSec follows untrusted data (requests, files, environment variables and more) through your running program and reports when it reaches a risky operation: a SQL query, a shell command, deserialization, a file path. Each event names the operation, the line of code, the value it received and where the untrusted part came from. This server reads those events; it never changes anything on your account.

## What you need

- An EyalSec account and an API key. Create the key on your dashboard under **Settings > API access**. A **read-only key** is all this server needs, and it is the one we recommend: see [API keys](https://eyalsec.com/docs/api-keys).
- Python 3.10 or newer, or [`uv`](https://docs.astral.sh/uv/), which runs the server without a separate install.

No account yet? [Book a live demo](https://eyalsec.com/contact) and we will set one up with you. Pricing is at [eyalsec.com/pricing](https://eyalsec.com/pricing).

## Set it up

The server speaks MCP over stdio. Your client starts it with `uvx eyalsec-mcp` (or `eyalsec-mcp` after `pipx install eyalsec-mcp`) and passes the key in the environment.

### Claude Code

```bash
claude mcp add eyalsec -e EYALSEC_API_KEY=es2_your_read_only_key -- uvx eyalsec-mcp
```

### Claude Desktop

Add this to `claude_desktop_config.json` (Settings > Developer > Edit Config), then restart Claude Desktop:

```json
{
  "mcpServers": {
    "eyalsec": {
      "command": "uvx",
      "args": ["eyalsec-mcp"],
      "env": {
        "EYALSEC_API_KEY": "es2_your_read_only_key"
      }
    }
  }
}
```

### Cursor

Add the same block to `~/.cursor/mcp.json` (every project) or `.cursor/mcp.json` (one project):

```json
{
  "mcpServers": {
    "eyalsec": {
      "command": "uvx",
      "args": ["eyalsec-mcp"],
      "env": {
        "EYALSEC_API_KEY": "es2_your_read_only_key"
      }
    }
  }
}
```

### Docker

```bash
docker build -t eyalsec-mcp https://github.com/EyalSec/eyalsec-mcp.git
docker run --rm -i -e EYALSEC_API_KEY=es2_your_read_only_key eyalsec-mcp
```

Use the second line as the command in any client's configuration.

### Any other MCP client

Run `uvx eyalsec-mcp` as a stdio server with `EYALSEC_API_KEY` set. To check the key before wiring it into a client:

```bash
EYALSEC_API_KEY=es2_your_read_only_key uvx eyalsec-mcp --check
```

It calls the API once and prints the account it reached, the key's scope and the number of machines.

### Settings

| Variable | Required | Meaning |
|---|---|---|
| `EYALSEC_API_KEY` | yes | Your API key, from **Settings > API access**. Read-only is enough. |
| `EYALSEC_URL` | no | Your EyalSec address. Defaults to `https://eyalsec.com`; set it only if your account lives on another domain. Must be `https://`. |

## What it can do

Every tool is a read. The server has no code path that adds, changes or deletes anything, so even a full-access key cannot be used to write through it.

| Tool | What it answers |
|---|---|
| `search_events` | Your events, newest or most severe first, with the events page's filters: product, severity, dates, machine, taint source, impact class, label, sink pattern, run, and the advanced condition builder. Follows the API's paging for you. |
| `get_event` | One event in full: stack trace, where the data came in, where the value was created, nearby source code when the machine sends it, your note, and the runs that produced it. |
| `event_stats` | The dashboard summary: totals, the last hour, day and week, top event types and a 14-day timeline. |
| `event_counts` | How many events each product's list holds, live versus suppressed, and the count toward your monthly quota. |
| `list_event_names` | The distinct sink labels across your events, handy for building a filter. |
| `event_map` | The es-python events as a graph: sources, the files data was read from, and the operations it reached. |
| `list_runs` | The program invocations behind your events, with their command lines (secrets masked). |
| `ci_findings` | What runs on one machine reported since a moment, counted by severity, with which findings are new. |
| `list_machines` | Every machine: status, OS target, product, installed and newest build, and whether an update is waiting. |
| `supported_targets` | The Linux distributions, architectures and Python versions es-python installs on. |
| `list_rules`, `list_filters`, `get_taint_settings`, `get_event_uniqueness`, `list_rule_templates` | How your account and each machine are configured. |
| `list_labels`, `list_saved_searches` | Your triage labels and saved searches. |
| `get_account`, `list_activity` | Your profile and limits, your key's scope and expiry (never the key), setup progress, and the activity log. |

Some things to try:

- "Summarize this week's critical and high events by machine."
- "Open the newest SQL injection event and explain the path from the request to the query."
- "Which runs of `app.py` produced command-injection events yesterday?"
- "Do any machines have an update waiting or an install stuck in pending?"

## Safety notes

- **Events contain untrusted text.** A value that reached a sink, a stack trace or a command line came from a monitored program and its inputs, which can include text an attacker wrote. The server tells the assistant to treat it as data, not instructions; keep human review on anything the assistant proposes to do with it.
- **Use a read-only key.** It can read everything this server reads and nothing more. A key can also carry an expiry date.
- **The key stays with you.** It is read from the environment, sent only to your EyalSec address over HTTPS, and never returned by any tool. Plain HTTP is refused except to `localhost`.
- The API's [rate limits](https://eyalsec.com/docs/api#rate-limits) apply. `search_events` reads at most 10 pages per call and hands back a cursor for the rest.

## Development

```bash
git clone https://github.com/EyalSec/eyalsec-mcp && cd eyalsec-mcp
python -m venv .venv && . .venv/bin/activate
pip install -e '.[test]'
pytest
```

The tests run against a fake API. To also run one read-only pass against your own account, set `EYALSEC_LIVE=1` and `EYALSEC_API_KEY`.

## Help

Questions and bug reports are welcome in [issues](https://github.com/EyalSec/eyalsec-mcp/issues), or write to support@eyalsec.com. Please send security reports to security@eyalsec.com rather than a public issue.

## License

MIT. See [LICENSE](LICENSE). The license covers this MCP server; your EyalSec account is governed by the [EyalSec terms](https://eyalsec.com/legal/terms).
