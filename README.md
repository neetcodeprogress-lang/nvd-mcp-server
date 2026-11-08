# NVD MCP Server

An [MCP](https://modelcontextprotocol.io) server that lets AI assistants look up
vulnerabilities (CVEs) in NIST's National Vulnerability Database. Ask your assistant questions such as
"what's being actively exploited in the software we run?" and it searches the NVD for you.

## Tools

| Tool | What it answers |
|:--|:--|
| `search_cves` | "What's out there for this product?" Keyword search, newest first, up to 50 results. |
| `get_cve` | "Tell me everything about CVE-2024-21762." One CVE with its full description. |

Each result includes the CVSS score and severity, the publish date, and whether CISA
lists it as actively exploited (the KEV catalog), so the assistant can filter and rank.

## Setup

Needs [uv](https://docs.astral.sh/uv/) and git. uv installs Python 3.12+ and the
dependencies on first run.

```bash
git clone https://github.com/neetcodeprogress-lang/nvd-mcp-server.git
```

Then add the server to your MCP client. Most clients use a JSON config like this
(see your client's docs for where the file goes):

```json
{
  "mcpServers": {
    "nvd": {
      "command": "uv",
      "args": ["--directory", "/path/to/nvd-mcp-server", "run", "python", "-m", "nvd_mcp.server"]
    }
  }
}
```

Replace `/path/to/nvd-mcp-server` with the folder you cloned into
(for example `C:\Users\you\nvd-mcp-server` on Windows).

**For example, in Claude Code**, one command does it (`--scope user` makes it
available in every project):

```bash
claude mcp add nvd --scope user -- uv --directory /path/to/nvd-mcp-server run python -m nvd_mcp.server
```

Tested with Claude Code. The server runs locally, so browser-based assistants that
only connect to remote servers can't use it.

### Optional: NVD API key

The server works without a key. With one, NVD allows 10× more requests, so the
server waits 0.6 seconds between requests instead of 6.
[Request a free key from NIST](https://nvd.nist.gov/developers/request-an-api-key), then
pass it as the `NVD_API_KEY` environment variable: add `"env": { "NVD_API_KEY": "your-key" }`
to the JSON config, or in Claude Code use `-e`:

```bash
claude mcp add nvd --scope user -e NVD_API_KEY=your-key -- uv --directory /path/to/nvd-mcp-server run python -m nvd_mcp.server
```

(Already added it without a key? Run `claude mcp remove nvd --scope user` first.)

The server reads the key from the environment and never stores it. Your MCP client
keeps it in its own config. Claude Code, for example, stores it in plain text in
`~/.claude.json`, readable only by your user account.

## Demo: no tools vs. web search vs. this server

> **What are the recent critical FortiOS vulnerabilities, and are any being actively exploited?**

Asked three times on 2026-11-08 with the same model (Claude Opus 5.5) and nothing else
enabled:

| | No tools | Web search | This server |
|:--|:--|:--|:--|
| Source | Training data (to ~mid-2026) | 15 websites, official and news | NVD only |
| Critical CVEs on CISA's exploited list found (NVD lists 3) | 2 | 2 | 3 |
| CVSS scores | Approximate | "9.4–9.8, sources differ" | NVD's exact score |
| Extra context (fixed versions, news) | Some | Most | Least |
| Time | 28 s | 76 s | 35 s |
| Input tokens | ~3k | ~48k | ~41k |

The three it found: **CVE-2026-24858** (FortiCloud SSO login bypass),
**CVE-2025-25249** (heap overflow, remote code execution) and **CVE-2025-59718**
(FortiCloud SSO bypass via a crafted SAML response), all CVSS 9.8.

**Takeaway:** for public data like this, web search gets close and adds more context.
This server's edge is one official source with the same structured fields every time,
which matters most when an agent or a script acts on the results. It's also faster,
and it works where web search is turned off. MCP pays off most for data the web
can't reach.

## Design notes

- **Retries:** network errors, 429 and 5xx are retried with exponential backoff
  (honoring `Retry-After`, capped at 60s). 403 and other 4xx fail fast with a clear message.
- **Rate limits:** pauses between requests keep under NVD's published limits
  (5 requests / 30s without a key, 50 with one).
- **Newest first:** NVD returns results oldest first and has no sort option. Found in an
  end-to-end run: "recent" searches stopped at 2022. The server now reads the total
  from the first page and jumps to the newest results.
- **50-result cap:** 100 results came to ~50k characters, over Claude Code's limit
  for one tool result. 50 keeps a search well under it.

## Known limitations

- Keyword search is literal: "FortiGate" and "FortiOS" return different CVEs.
- Searches return the newest 50 matches, so older CVEs can be left out.
- "Actively exploited" means listed in CISA's KEV catalog. A description that mentions
  exploitation doesn't set it.
- NVD pages by offset, so a CVE published mid-search can shift results by one.
- NVD lists affected versions, not fixed ones, so check the vendor's advisory for patches.

## Development

```bash
uv sync          # install dependencies, including test tools
uv run pytest    # 45 tests; HTTP is faked with respx, so they never call the real NVD API
```

## How it was built

Built to learn how to implement an MCP server end to end: designing tools an AI
assistant can use well, wrapping a real public API reliably, and testing it.
Built with Claude Code as a pair programmer: it wrote most of the Python; I made the
design decisions (retry policy, result ordering, result limits) and verified each piece
with tests and live runs against NVD.
