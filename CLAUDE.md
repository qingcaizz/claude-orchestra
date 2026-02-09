# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Agent Viewer is a web-based kanban board for managing multiple Claude Code AI agents running in tmux sessions. It provides a central UI to spawn, monitor, message, and clean up concurrent Claude Code instances.

## Commands

```bash
npm start                          # Start server at http://localhost:4200
HOST=0.0.0.0 PORT=3000 npm start  # Bind to network on custom port
```

There is no build step, no test suite, and no linter configured. The app runs directly with Node.js.

## Architecture

This is a two-file application with no frameworks or build tooling:

- **`server.js`** — Express backend handling agent lifecycle, tmux integration, state detection, and SSE broadcasting
- **`public/index.html`** — Entire frontend (HTML/CSS/JS) in a single file with vanilla JavaScript

### Backend Core Systems (server.js)

**Agent Registry**: In-memory object + `.agent-registry.json` persistence. Tracks agent label, project path, prompt, state, and timestamps. Auto-recovers on restart.

**State Detection** (`detectAgentState()`): Polls tmux pane output every 3 seconds. Classifies agents as `running`, `idle`, or `completed` by pattern-matching Claude Code's terminal UI signals — "esc to interrupt" means running; empty prompts and permission requests mean idle.

**Tmux Integration**: Spawns agents via `tmux new-session`, captures output via `tmux capture-pane -e -p`, sends messages via `tmux send-keys`. All external commands have timeouts (5-15s).

**Auto-Discovery**: Scans all tmux sessions, builds process trees to detect Claude descendants, and adds discovered sessions to the registry.

**LLM Label Generation**: Spawns a quick heuristic label immediately, then asynchronously calls Claude Haiku via CLI to generate a smarter label. Non-blocking — UI updates via SSE when the upgraded label arrives.

**SSE Endpoint** (`GET /api/events`): Broadcasts full agent state to all connected clients at `POLL_INTERVAL` (3s default).

### Frontend (public/index.html)

Three-column kanban board (Running/Idle/Completed) with SSE-driven updates. Includes a full ANSI-to-HTML converter supporting 16/256/24-bit color. Drag-and-drop for cards and file uploads. Terminal-inspired dark aesthetic.

### API Routes

| Method | Path | Purpose |
|--------|------|---------|
| GET | `/api/agents` | List all agents with state |
| POST | `/api/agents` | Spawn new agent |
| POST | `/api/agents/:name/send` | Send message / respawn |
| POST | `/api/agents/:name/upload` | Upload file to agent |
| DELETE | `/api/agents/:name` | Kill agent session |
| DELETE | `/api/agents/:name/cleanup` | Remove from registry |
| DELETE | `/api/cleanup/completed` | Bulk cleanup completed |
| GET | `/api/agents/:name/output` | Fetch terminal output |
| GET | `/api/events` | SSE real-time updates |

## Key Patterns

- Shell arguments are escaped with single-quote replacement (`message.replace(/'/g, "'\\''")`)
- External commands use `exec()` (async) with timeouts, not `execSync()`, to avoid blocking
- Agent session names follow the format `agent-{label}` (lowercase, hyphenated)
- Multipart file upload parsing is done manually without libraries
- System dependencies: **tmux** and **claude** CLI must be available on PATH
