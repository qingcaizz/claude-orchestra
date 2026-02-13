const express = require('express');
const { exec } = require('child_process');
const path = require('path');
const fs = require('fs');
const os = require('os');
const pty = require('node-pty');

const app = express();
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

const HOST = process.env.HOST || '0.0.0.0';
const PORT = process.env.PORT || 4200;
const REGISTRY_FILE = path.join(__dirname, '.agent-registry.json');
const POLL_INTERVAL = 3000;
const SPAWN_PREFIX = 'agent-';
const OUTPUT_BUFFER_MAX = 5000; // max lines per session buffer

// ─── Team Data Paths ────────────────────────────────────────────────────────
const TEAMS_DIR = path.join(os.homedir(), '.claude', 'teams');
const TASKS_DIR = path.join(os.homedir(), '.claude', 'tasks');

// ─── Agent Registry ──────────────────────────────────────────────────────────

let registry = {};

function loadRegistry() {
  try {
    if (fs.existsSync(REGISTRY_FILE)) {
      registry = JSON.parse(fs.readFileSync(REGISTRY_FILE, 'utf-8'));
    }
  } catch (e) {
    console.error('Failed to load registry:', e.message);
    registry = {};
  }
}

function saveRegistry() {
  try {
    fs.writeFileSync(REGISTRY_FILE, JSON.stringify(registry, null, 2));
  } catch (e) {
    console.error('Failed to save registry:', e.message);
  }
}

// ─── PTY Session Manager (replaces tmux) ─────────────────────────────────────

const sessions = new Map(); // name → { pty, outputBuffer, projectPath, createdAt }

function createSession(name, cwd, command, args) {
  const shell = process.platform === 'win32' ? 'cmd.exe' : '/bin/bash';
  const shellArgs = process.platform === 'win32'
    ? ['/c', command + (args ? ' ' + args : '')]
    : ['-c', command + (args ? ' ' + args : '')];

  const ptyProcess = pty.spawn(shell, shellArgs, {
    name: 'xterm-256color',
    cols: 120,
    rows: 40,
    cwd: cwd,
    env: { ...process.env, TERM: 'xterm-256color' },
  });

  const session = {
    pty: ptyProcess,
    outputBuffer: [],
    projectPath: cwd,
    createdAt: Date.now(),
    dead: false,
  };

  ptyProcess.onData((data) => {
    session.outputBuffer.push(data);
    // Trim buffer if it gets too large (by joining, splitting lines, and keeping last N)
    if (session.outputBuffer.length > OUTPUT_BUFFER_MAX * 2) {
      const full = session.outputBuffer.join('');
      const lines = full.split('\n');
      const trimmed = lines.slice(-OUTPUT_BUFFER_MAX);
      session.outputBuffer = [trimmed.join('\n')];
    }
  });

  ptyProcess.onExit(({ exitCode }) => {
    console.log(`[PTY] Session ${name} exited with code ${exitCode}`);
    session.dead = true;
  });

  sessions.set(name, session);
  return ptyProcess;
}

function listSessions() {
  const result = [];
  for (const [name, session] of sessions) {
    result.push({
      name,
      activity: Date.now(),
      created: session.createdAt,
    });
  }
  return result;
}

function capturePaneOutput(sessionName, lines = 200) {
  const session = sessions.get(sessionName);
  if (!session) return '';
  const full = session.outputBuffer.join('');
  const allLines = full.split('\n');
  return allLines.slice(-lines).join('\n');
}

function getSessionPid(sessionName) {
  const session = sessions.get(sessionName);
  if (!session || session.dead) return null;
  return session.pty.pid;
}

function getPaneCurrentPath(sessionName) {
  const session = sessions.get(sessionName);
  return session ? session.projectPath : '';
}

function isProcessAlive(pid) {
  if (!pid) return false;
  try {
    process.kill(pid, 0);
    return true;
  } catch {
    return false;
  }
}

// ─── Label Generation (LLM-powered) ─────────────────────────────────────────

console.log('[LABEL] Using claude CLI for smart label generation');

function fallbackLabel(text) {
  if (!text) return 'task-' + Date.now().toString(36);
  const stop = new Set(['the','a','an','in','on','at','to','for','of','with','and','or','but','is','are','was','were','be','been','have','has','had','do','does','did','will','would','could','should','can','that','this','it','its','i','me','my','we','our','you','your','they','them','their','he','him','his','she','her','from','by','as','all','so','if','then','than','too','very','just','about','up','out','into','over','please','make']);
  const words = text.toLowerCase().replace(/[^a-z0-9\s]/g, '').split(/\s+/).filter(w => w && !stop.has(w));
  return words.slice(0, 4).join('-') || 'task-' + Date.now().toString(36);
}

function callClaude(systemPrompt, userText) {
  return new Promise((resolve, reject) => {
    const prompt = `${systemPrompt}\n\n${userText}`;
    // Windows-compatible: use spawn with pipe via cmd
    const escaped = prompt.replace(/"/g, '\\"');
    const cmd = process.platform === 'win32'
      ? `echo "${escaped}" | claude --print --model haiku 2>NUL`
      : `echo '${prompt.replace(/'/g, "'\\''")}' | claude --print --model haiku 2>/dev/null`;
    exec(
      cmd,
      { encoding: 'utf-8', timeout: 15000, shell: process.platform === 'win32' ? 'cmd.exe' : '/bin/bash' },
      (err, stdout) => {
        if (err) {
          console.log(`[LABEL-CLI] Failed: ${err.message.substring(0, 100)}`);
          return reject(err);
        }
        const result = stdout.trim();
        console.log(`[LABEL-CLI] Response: "${result}"`);
        resolve(result);
      }
    );
  });
}

async function generateSmartLabel(text) {
  try {
    const raw = await callClaude(
      'Generate a short label (2-4 lowercase words, hyphenated, no quotes) summarizing this coding task. Reply with ONLY the label.',
      text.substring(0, 300)
    );
    const label = raw.toLowerCase().replace(/[^a-z0-9-\s]/g, '').replace(/\s+/g, '-').replace(/-+/g, '-').replace(/^-|-$/g, '');
    if (label && label.length > 2 && label.length < 60) return label;
  } catch (e) {
    console.log(`[LABEL] LLM fallback: ${e.message}`);
  }
  return fallbackLabel(text);
}

async function refreshDiscoveredLabel(sessionName) {
  const reg = registry[sessionName];
  if (!reg || !reg.discovered || reg.labelRefreshed) return;

  const rawOutput = capturePaneOutput(sessionName, 30);
  const output = stripAnsi(rawOutput).trim();
  console.log(`[LABEL] Refreshing label for ${sessionName}, output length: ${output.length}`);
  if (!output || output.length < 20) {
    console.log(`[LABEL] Not enough output yet for ${sessionName}`);
    return;
  }

  reg.labelRefreshed = true;
  try {
    const label = await callClaude(
      'This is terminal output from a Claude Code AI agent working on a coding task. Generate a short label (2-4 lowercase words, hyphenated, no quotes) summarizing what this agent is doing. Reply with ONLY the label.',
      output.substring(0, 500)
    );
    console.log(`[LABEL] Haiku returned for ${sessionName}: "${label}"`);
    const clean = label.toLowerCase().replace(/[^a-z0-9-\s]/g, '').replace(/\s+/g, '-').replace(/-+/g, '-').replace(/^-|-$/g, '');
    if (clean && clean.length > 2 && clean.length < 60) {
      reg.label = clean;
      saveRegistry();
      console.log(`[LABEL] Discovered agent ${sessionName} labeled: ${clean}`);
    } else {
      console.log(`[LABEL] Rejected cleaned label: "${clean}"`);
    }
  } catch (e) {
    console.log(`[LABEL] Failed for ${sessionName}: ${e.message}`);
    reg.labelRefreshed = false;
  }
}

// ─── ANSI Stripping ──────────────────────────────────────────────────────────

function stripAnsi(str) {
  return str.replace(/\x1B(?:\[[0-9;]*[a-zA-Z]|\][^\x07]*\x07|\([A-Z0-9])/g, '')
            .replace(/\x1B\[[\?]?[0-9;]*[a-zA-Z]/g, '')
            .replace(/\x1B[^[\]()][^\x1B]*/g, '')
            .replace(/[\x00-\x08\x0B\x0C\x0E-\x1F]/g, '');
}

// ─── Agent Lifecycle ─────────────────────────────────────────────────────────

/**
 * Poll pty output until Claude Code is ready for input (showing prompt).
 * Returns true if ready, false if timed out.
 */
async function waitForClaudeReady(sessionName, timeoutMs = 30000) {
  const pollInterval = 500;
  const maxAttempts = Math.ceil(timeoutMs / pollInterval);

  for (let i = 0; i < maxAttempts; i++) {
    await new Promise(r => setTimeout(r, pollInterval));

    const rawOutput = capturePaneOutput(sessionName, 30);
    const output = stripAnsi(rawOutput);
    const lines = output.split('\n').filter(l => l.trim() !== '');
    if (lines.length === 0) continue;

    const recentText = lines.slice(-8).map(l => l.trim()).join('\n');

    // Detect interactive prompts that block Claude startup and dismiss them.
    const isTrustPrompt = /No, exit/i.test(recentText) && /Yes, I accept/i.test(recentText);
    const isSettingsError = /Exit and fix manually/i.test(recentText) && /Continue without/i.test(recentText);
    const isInfoPrompt = /Enter to confirm/i.test(recentText)
      && !isTrustPrompt && !isSettingsError
      && !/space to select/i.test(recentText)
      && !/to navigate/i.test(recentText);

    if (isTrustPrompt || isSettingsError) {
      console.log(`[SPAWN] Startup prompt detected for ${sessionName}, selecting option 2...`);
      try {
        const session = sessions.get(sessionName);
        if (session) {
          session.pty.write('\x1B[B'); // Down arrow
          await new Promise(r => setTimeout(r, 200));
          session.pty.write('\r'); // Enter
        }
      } catch (e) {
        console.log(`[SPAWN] Failed to dismiss prompt for ${sessionName}: ${e.message}`);
      }
      continue;
    }

    if (isInfoPrompt) {
      console.log(`[SPAWN] Info prompt detected for ${sessionName}, pressing Enter...`);
      try {
        const session = sessions.get(sessionName);
        if (session) {
          session.pty.write('\r');
        }
      } catch (e) {
        console.log(`[SPAWN] Failed to dismiss info prompt for ${sessionName}: ${e.message}`);
      }
      continue;
    }

    // If Claude is actively running a task, it's past startup prompts
    if (/esc to interrupt/i.test(recentText)) return true;

    // Check if Claude is showing its input prompt (ready for input)
    const lastLine = lines[lines.length - 1].trim();
    if (/^>\s*$/.test(lastLine) || /^❯\s*$/.test(lastLine) || /^❯\s+\S/.test(lastLine)) {
      return true;
    }

    // Also ready if showing common idle signals
    if (/what.*would.*like/i.test(recentText) || /can i help/i.test(recentText)) {
      return true;
    }
  }

  console.log(`[SPAWN] waitForClaudeReady timed out for ${sessionName} after ${timeoutMs}ms`);
  return false;
}

async function spawnAgent(projectPath, prompt) {
  // Expand ~ to home directory
  if (projectPath.startsWith('~')) {
    projectPath = path.join(os.homedir(), projectPath.slice(1));
  }
  // Resolve to absolute path
  projectPath = path.resolve(projectPath);

  const quickLabel = fallbackLabel(prompt);
  const safeName = SPAWN_PREFIX + quickLabel.replace(/[^a-zA-Z0-9_-]/g, '-');

  // Deduplicate if name exists
  let finalName = safeName;
  if (sessions.has(finalName) || registry[finalName]) {
    finalName = safeName + '-' + Date.now().toString(36).slice(-4);
  }

  // Verify project path exists
  if (!fs.existsSync(projectPath)) {
    throw new Error(`Project path does not exist: ${projectPath}`);
  }

  const claudeCmd = 'claude --dangerously-skip-permissions';

  console.log(`[SPAWN] quickLabel=${quickLabel} name=${finalName}`);
  console.log(`[SPAWN] projectPath=${projectPath}`);
  console.log(`[SPAWN] cmd: ${claudeCmd}`);

  createSession(finalName, projectPath, claudeCmd);

  registry[finalName] = {
    label: quickLabel,
    projectPath,
    prompt,
    createdAt: Date.now(),
    state: 'running',
    initialPromptSent: false,
  };
  saveRegistry();

  // Async: upgrade label via LLM in background
  generateSmartLabel(prompt).then(smartLabel => {
    if (smartLabel !== quickLabel && registry[finalName]) {
      console.log(`[SPAWN] label upgraded: "${quickLabel}" → "${smartLabel}"`);
      registry[finalName].label = smartLabel;
      saveRegistry();
    }
  }).catch(e => {
    console.log(`[SPAWN] async label upgrade failed, keeping fallback: ${e.message}`);
  });

  if (prompt) {
    waitForClaudeReady(finalName).then(ready => {
      if (!ready) {
        console.log(`[SPAWN] Claude not ready for ${finalName}, sending prompt anyway`);
      }
      console.log(`[SPAWN] sending initial prompt to ${finalName}: ${prompt.substring(0, 80)}...`);
      const sent = sendToAgent(finalName, prompt);
      console.log(`[SPAWN] send result: ${sent}`);
      if (registry[finalName]) {
        registry[finalName].initialPromptSent = true;
        saveRegistry();
      }
    });
  }

  return finalName;
}

function sendToAgent(sessionName, message) {
  try {
    const session = sessions.get(sessionName);
    if (!session || session.dead) {
      console.error(`[SEND] Session ${sessionName} not found or dead`);
      return false;
    }
    console.log(`[SEND] to ${sessionName}: ${message.substring(0, 100)}${message.length > 100 ? '...' : ''}`);
    session.pty.write(message + '\r');
    console.log(`[SEND] success`);
    return true;
  } catch (e) {
    console.error(`[SEND] FAILED to ${sessionName}:`, e.message);
    return false;
  }
}

function killAgent(sessionName) {
  const session = sessions.get(sessionName);
  if (session) {
    try {
      session.pty.kill();
    } catch {
      // Process might already be dead
    }
    session.dead = true;
    sessions.delete(sessionName);
  }
  if (registry[sessionName]) {
    registry[sessionName].state = 'completed';
    registry[sessionName].completedAt = Date.now();
    saveRegistry();
  }
}

// ─── State Detection ─────────────────────────────────────────────────────────

function detectAgentState(sessionName) {
  const reg = registry[sessionName];
  if (!reg) return 'unknown';

  const session = sessions.get(sessionName);
  if (!session) return 'completed';

  if (session.dead) return 'completed';

  const pid = getSessionPid(sessionName);
  if (!isProcessAlive(pid)) return 'completed';

  // Grace period: if a message was recently sent, treat as running
  if (reg.lastMessageSentAt && (Date.now() - reg.lastMessageSentAt) < 10000) {
    return 'running';
  }

  const rawOutput = capturePaneOutput(sessionName, 50);
  const output = stripAnsi(rawOutput);
  const lines = output.split('\n').filter(l => l.trim() !== '');

  if (lines.length === 0) return 'running';

  const recentText = lines.slice(-8).map(l => l.trim()).join('\n');

  // Check for interactive TUI prompts FIRST
  const interactivePromptPatterns = [
    /enter to select/i,
    /space to select/i,
    /to navigate.*esc to cancel/i,
    /Allow\s+(once|always)/i,
    /yes.*no.*always allow/i,
    /ctrl.g to edit/i,
  ];

  if (interactivePromptPatterns.some(p => p.test(recentText))) {
    return 'idle';
  }

  // Claude Code's status bar shows "esc to interrupt" only when actively running
  if (/esc to interrupt/i.test(recentText)) {
    return 'running';
  }

  // Filter out persistent UI elements
  const uiNoise = [
    /bypass permissions/i,
    /shift.?tab to cycle/i,
    /ctrl.?t to hide/i,
    /^[─━═]+$/,
    /^❯\s*$/,
  ];
  const contentLines = lines.filter(l => !uiNoise.some(p => p.test(l.trim())));

  if (contentLines.length === 0) return 'running';

  const lastLine = contentLines[contentLines.length - 1].trim();

  const idlePatterns = [
    /^>\s*$/,
    /^>\s+$/,
    /^\$\s*$/,
    /^❯\s*$/,
    /^❯\s+\S/,
    /has completed/i,
    /what.*would.*like/i,
    /anything.*else/i,
    /can i help/i,
    /waiting for input/i,
  ];

  if (idlePatterns.some(p => p.test(lastLine))) {
    return 'idle';
  }

  const recentContent = contentLines.slice(-8).map(l => l.trim()).join('\n');

  const waitingForInputPatterns = [
    /do you want to proceed/i,
    /shall I proceed/i,
    /should I proceed/i,
    /approve|deny|reject/i,
    /\(y\/n\)/i,
    /enter a value|enter to confirm/i,
    /select.*option/i,
    /choose.*from/i,
    /press enter to send/i,
  ];

  if (waitingForInputPatterns.some(p => p.test(recentContent))) {
    return 'idle';
  }

  return 'running';
}

/**
 * Detect the type of interactive prompt Claude is showing (if any).
 */
function detectPromptType(sessionName) {
  const rawOutput = capturePaneOutput(sessionName, 50);
  const output = stripAnsi(rawOutput);
  const lines = output.split('\n').filter(l => l.trim() !== '');
  if (lines.length === 0) return null;

  const recentText = lines.slice(-20).map(l => l.trim()).join('\n');

  if (/space to select/i.test(recentText) && /enter to confirm/i.test(recentText)) {
    return 'multiselect';
  }

  if (/allow\s+(once|always)/i.test(recentText) && /deny/i.test(recentText)) {
    return 'permission';
  }

  if (/ctrl.g to edit/i.test(recentText) ||
      (/manually approve/i.test(recentText) && /\d\.\s/.test(recentText)) ||
      (/execute.*plan/i.test(recentText) && /\d\.\s/.test(recentText))) {
    return 'plan';
  }

  if (/enter to select/i.test(recentText) && /to navigate/i.test(recentText)) {
    return 'select';
  }

  if (/\(y\/n\)/i.test(recentText) || (/yes.*no/i.test(recentText) && /do you want|shall i|should i/i.test(recentText))) {
    return 'yesno';
  }

  const numberedLines = recentText.split('\n').filter(l => /^\s*\d+[.)]\s/.test(l));
  if (numberedLines.length >= 2) {
    return 'select';
  }

  return null;
}

const NOISE_PATTERNS = [
  /bypass permissions/i,
  /shift.?tab to cycle/i,
  /ctrl.?t to hide/i,
  /press enter to send/i,
  /waiting for input/i,
  /^[>❯$]\s*$/,
  /^\s*$/,
];

function getLastActivity(sessionName) {
  const rawOutput = capturePaneOutput(sessionName, 30);
  const lines = rawOutput.split('\n');

  const meaningful = [];
  for (let i = lines.length - 1; i >= 0 && meaningful.length < 3; i--) {
    const clean = stripAnsi(lines[i]).trim();
    if (!clean) continue;
    if (NOISE_PATTERNS.some(p => p.test(clean))) continue;
    meaningful.unshift(lines[i]);
  }
  return meaningful.join('\n');
}

function buildAgentInfo(sessionName) {
  const reg = registry[sessionName] || {};
  const state = detectAgentState(sessionName);

  if (registry[sessionName]) {
    if (state === 'completed' && registry[sessionName].state !== 'completed') {
      // Clean up dead session
      const session = sessions.get(sessionName);
      if (session) {
        try { session.pty.kill(); } catch {}
        sessions.delete(sessionName);
      }
      registry[sessionName].completedAt = registry[sessionName].completedAt || Date.now();
    }
    registry[sessionName].state = state;
    if (state === 'idle' && !registry[sessionName].idleSince) {
      registry[sessionName].idleSince = Date.now();
    } else if (state !== 'idle') {
      delete registry[sessionName].idleSince;
      delete registry[sessionName].lastMessageSentAt;
    }
  }

  const promptType = state !== 'completed' ? detectPromptType(sessionName) : null;

  return {
    name: sessionName,
    label: reg.label || sessionName,
    projectPath: reg.projectPath || '',
    prompt: reg.prompt || '',
    state,
    promptType,
    createdAt: reg.createdAt || 0,
    idleSince: reg.idleSince || null,
    completedAt: reg.completedAt || null,
    lastActivity: state !== 'completed' ? getLastActivity(sessionName) : '',
    discovered: reg.discovered || false,
  };
}

// ─── Aggregation ─────────────────────────────────────────────────────────────

function getAllAgents() {
  // Mark dead registry entries as completed (sessions that no longer exist)
  for (const name of Object.keys(registry)) {
    const session = sessions.get(name);
    if (!session && registry[name].state !== 'completed') {
      registry[name].state = 'completed';
      registry[name].completedAt = registry[name].completedAt || Date.now();
    } else if (session && session.dead && registry[name].state !== 'completed') {
      registry[name].state = 'completed';
      registry[name].completedAt = registry[name].completedAt || Date.now();
      sessions.delete(name);
    }
  }

  // Build agent info for all known sessions
  const agents = [];
  for (const name of Object.keys(registry)) {
    agents.push(buildAgentInfo(name));
  }

  saveRegistry();
  return agents;
}

// ─── Team Data Functions ─────────────────────────────────────────────────

function scanTeams() {
  const teams = [];
  try {
    if (!fs.existsSync(TEAMS_DIR)) return teams;
    const entries = fs.readdirSync(TEAMS_DIR, { withFileTypes: true });
    for (const entry of entries) {
      if (entry.isDirectory()) {
        const config = readTeamConfig(entry.name);
        if (config) {
          const tasks = readTeamTasks(entry.name);
          const activeTasks = tasks.filter(t => t.status === 'in_progress').length;
          teams.push({
            name: entry.name,
            description: config.description || '',
            memberCount: (config.members || []).length,
            activeTasks,
            totalTasks: tasks.length,
            hasActiveMembers: activeTasks > 0,
          });
        }
      }
    }
  } catch (e) {
    console.error('[TEAMS] Failed to scan teams:', e.message);
  }
  return teams;
}

function readTeamConfig(teamName) {
  try {
    const configPath = path.join(TEAMS_DIR, teamName, 'config.json');
    if (!fs.existsSync(configPath)) return null;
    return JSON.parse(fs.readFileSync(configPath, 'utf-8'));
  } catch (e) {
    console.error(`[TEAMS] Failed to read config for ${teamName}:`, e.message);
    return null;
  }
}

function readTeamTasks(teamName) {
  const tasks = [];
  try {
    const tasksDir = path.join(TASKS_DIR, teamName);
    if (!fs.existsSync(tasksDir)) return tasks;
    const files = fs.readdirSync(tasksDir).filter(f => f.endsWith('.json'));
    for (const file of files) {
      try {
        const data = JSON.parse(fs.readFileSync(path.join(tasksDir, file), 'utf-8'));
        tasks.push(data);
      } catch (e) {
        // skip malformed task files
      }
    }
  } catch (e) {
    console.error(`[TEAMS] Failed to read tasks for ${teamName}:`, e.message);
  }
  return tasks;
}

function readTeamMessages(teamName, agentFilter) {
  const messages = [];
  try {
    const inboxDir = path.join(TEAMS_DIR, teamName, 'inboxes');
    if (!fs.existsSync(inboxDir)) return messages;
    const files = fs.readdirSync(inboxDir).filter(f => f.endsWith('.json'));
    for (const file of files) {
      const agentName = file.replace(/\.json$/, '');
      if (agentFilter && agentName !== agentFilter) continue;
      try {
        const data = JSON.parse(fs.readFileSync(path.join(inboxDir, file), 'utf-8'));
        const inbox = Array.isArray(data) ? data : (data.messages || []);
        for (const msg of inbox) {
          messages.push({
            to: agentName,
            from: msg.from || msg.sender || 'unknown',
            text: msg.text || msg.content || msg.message || '',
            timestamp: msg.timestamp || msg.sentAt || 0,
            read: msg.read || false,
            type: msg.type || 'message',
          });
        }
      } catch (e) {
        // skip malformed inbox files
      }
    }
    // Sort by timestamp
    messages.sort((a, b) => {
      const ta = typeof a.timestamp === 'string' ? new Date(a.timestamp).getTime() : a.timestamp;
      const tb = typeof b.timestamp === 'string' ? new Date(b.timestamp).getTime() : b.timestamp;
      return ta - tb;
    });
  } catch (e) {
    console.error(`[TEAMS] Failed to read messages for ${teamName}:`, e.message);
  }
  return messages;
}

function getFullTeamData(teamName) {
  const config = readTeamConfig(teamName);
  if (!config) return null;
  const tasks = readTeamTasks(teamName);
  const messages = readTeamMessages(teamName);

  // Enrich members with prompt data (already in config.members[].prompt)
  // Add member status summary
  const memberSummary = {};
  for (const m of (config.members || [])) {
    const name = m.name || m.agentId;
    const ownedTasks = tasks.filter(t => t.owner === name);
    const activeTasks = ownedTasks.filter(t => t.status === 'in_progress');
    memberSummary[name] = {
      prompt: m.prompt || '',
      model: m.model || '',
      agentType: m.agentType || '',
      activeTasks: activeTasks.length,
      totalTasks: ownedTasks.length,
    };
  }

  // Enrich with liveness data
  const liveness = getTeamMemberLiveness(teamName, config);
  for (const name of Object.keys(memberSummary)) {
    if (liveness[name]) {
      memberSummary[name].isAlive = liveness[name].isAlive;
      memberSummary[name].lastActiveAt = liveness[name].lastActiveAt;
    }
  }

  const events = aggregateTeamEvents(teamName);

  // Auto-discover members from events and tasks (in-process teammates not in config)
  const knownMembers = new Set((config.members || []).map(m => m.name || m.agentId));
  const ignoredActors = new Set(['unknown', 'viewer', 'system', 'team-lead']);
  const discoveredMembers = new Set();

  // Discover from events — only agent_message and task events (not noise)
  for (const ev of events) {
    if (ev.actor && !ignoredActors.has(ev.actor) && !knownMembers.has(ev.actor)) {
      // Only discover from meaningful event types
      if (['agent_message', 'task_started', 'task_completed', 'broadcast'].includes(ev.type)) {
        discoveredMembers.add(ev.actor);
      }
    }
  }

  // Discover from task owners
  for (const task of tasks) {
    if (task.owner && !knownMembers.has(task.owner)) {
      discoveredMembers.add(task.owner);
    }
  }

  // Add discovered members to config and memberSummary
  for (const name of discoveredMembers) {
    config.members.push({
      name,
      agentId: name,
      agentType: 'discovered',
      discovered: true,
    });
    const ownedTasks = tasks.filter(t => t.owner === name);
    const activeTasks = ownedTasks.filter(t => t.status === 'in_progress');
    memberSummary[name] = {
      prompt: '',
      model: '',
      agentType: 'discovered',
      activeTasks: activeTasks.length,
      totalTasks: ownedTasks.length,
      isAlive: false,
      lastActiveAt: null,
    };
  }

  return { config, tasks, messages, memberSummary, events };
}

// ─── JSONL Transcript Mining ─────────────────────────────────────────────────

/**
 * Build a map of agentId → memberName from team config
 */
function buildAgentIdToNameMap(config) {
  const map = {};
  for (const m of (config.members || [])) {
    if (m.agentId) map[m.agentId] = m.name || m.agentId;
    if (m.name) map[m.name] = m.name;
  }
  return map;
}

/**
 * Extract events from subagent JSONL transcript files.
 * Mines: SendMessage tool_use, TaskUpdate tool_use, assistant text output
 */
function extractTranscriptEvents(teamName) {
  const events = [];
  const config = readTeamConfig(teamName);
  if (!config) return events;

  const agentMap = buildAgentIdToNameMap(config);

  // --- Mine subagent JSONLs (if they exist — PTY-based teammates) ---
  const dirInfo = findLeadSessionDir(config);
  const subagentsDir = dirInfo ? path.join(dirInfo.sessionDir, 'subagents') : null;
  if (subagentsDir && fs.existsSync(subagentsDir)) {
    try {
      const files = fs.readdirSync(subagentsDir).filter(f =>
        f.endsWith('.jsonl') && !f.includes('prompt_suggestion')
      );
      for (const file of files) {
        const filePath = path.join(subagentsDir, file);
        let agentName = null;

        // Try to identify agent name from filename
        // Filename format: agent-a{shortId}.jsonl
        const idMatch = file.match(/agent-a([a-f0-9]+)\.jsonl/);
        if (idMatch) {
          // Match against config members by agentId
          for (const m of (config.members || [])) {
            if (m.agentId && m.agentId.includes(idMatch[1])) {
              agentName = m.name || m.agentId;
              break;
            }
          }
        }

        try {
          const content = fs.readFileSync(filePath, 'utf-8');
          const lines = content.split('\n').filter(l => l.trim());

          // If we couldn't match by ID, try first line for agent name hints
          if (!agentName && lines.length > 0) {
            try {
              const first = JSON.parse(lines[0]);
              const firstContent = JSON.stringify(first);
              for (const m of (config.members || [])) {
                if (m.name && m.name !== 'team-lead' && firstContent.includes(`"${m.name}"`)) {
                  agentName = m.name;
                  break;
                }
              }
              // Also try agentId field
              if (!agentName && first.agentId) {
                agentName = agentMap[first.agentId] || first.agentId;
              }
            } catch (e) { /* skip */ }
          }

          if (!agentName) agentName = file.replace('.jsonl', '');

          // Check first entry for teamName to verify this subagent belongs to this team
          let fileTeamName = null;
          for (const ln of lines.slice(0, 5)) {
            try { const e = JSON.parse(ln); if (e.teamName) { fileTeamName = e.teamName; break; } } catch {}
          }
          if (fileTeamName !== teamName) continue; // must match team, skip otherwise

          for (const line of lines) {
            try {
              const entry = JSON.parse(line);
              if (entry.teamName && entry.teamName !== teamName) continue;
              const entryType = entry.type || '';
              const contentBlocks = entry.content || (entry.message && entry.message.content) || [];
              if (!Array.isArray(contentBlocks)) continue;

              const ts = entry.timestamp || 0;

              for (const block of contentBlocks) {
                if (block.type !== 'tool_use') continue;

                // Extract SendMessage calls
                if (block.name === 'SendMessage' && block.input) {
                  const inp = block.input;
                  if (inp.content && (inp.type === 'message' || inp.type === 'broadcast')) {
                    const text = inp.content || '';
                    events.push({
                      type: inp.type === 'broadcast' ? 'broadcast' : 'agent_message',
                      timestamp: ts,
                      actor: agentName,
                      target: inp.recipient || 'all',
                      direction: `${agentName} → ${inp.recipient || 'all'}`,
                      summary: text.length > 500 ? text.substring(0, 500) + '...' : text,
                      detail: text,
                      source: 'transcript',
                    });
                  } else if (inp.type === 'shutdown_response') {
                    events.push({
                      type: 'shutdown_approved',
                      timestamp: ts,
                      actor: agentName,
                      target: null,
                      summary: `${agentName} approved shutdown`,
                      detail: '',
                      source: 'transcript',
                    });
                  }
                }

                // Extract TaskUpdate calls
                if (block.name === 'TaskUpdate' && block.input) {
                  const inp = block.input;
                  if (inp.status === 'in_progress') {
                    events.push({
                      type: 'task_started',
                      timestamp: ts,
                      actor: agentName,
                      target: null,
                      summary: `Started task #${inp.taskId}`,
                      detail: '',
                      source: 'transcript',
                    });
                  } else if (inp.status === 'completed') {
                    events.push({
                      type: 'task_completed',
                      timestamp: ts,
                      actor: agentName,
                      target: null,
                      summary: `Completed task #${inp.taskId}`,
                      detail: '',
                      source: 'transcript',
                    });
                  }
                }
              }

              // Note: assistant text blocks omitted to reduce noise
            } catch (e) { /* skip malformed lines */ }
          }
        } catch (e) {
          console.error(`[TRANSCRIPT] Failed to read ${filePath}: ${e.message}`);
        }
      }
    } catch (e) {
      console.error(`[TRANSCRIPT] Failed to scan subagents dir: ${e.message}`);
    }
  }

  // --- Mine lead JSONL for teammate-message entries ---
  // Lead JSONL can be found even without a session subdirectory (in-process teammates)
  const leadJsonlPath = findLeadJsonl(config);
  if (leadJsonlPath) {
    try {
      const content = fs.readFileSync(leadJsonlPath, 'utf-8');
      const lines = content.split('\n').filter(l => l.trim());
      for (const line of lines) {
        try {
          const entry = JSON.parse(line);

          // Strict teamName filter — only include entries belonging to this team
          if (entry.teamName !== teamName) continue;

          const msgContent = entry.content || (entry.message && entry.message.content) || '';
          const textStr = typeof msgContent === 'string' ? msgContent :
            (Array.isArray(msgContent) ? msgContent.filter(b => b.type === 'text').map(b => b.text).join('\n') : '');

          if (!textStr) continue;

          // Parse ALL <teammate-message> tags (multiple per entry)
          const tmRegex = /<teammate-message\s+teammate_id="([^"]+)"[^>]*?(?:summary="([^"]*)")?[^>]*>([\s\S]*?)<\/teammate-message>/g;
          let tmMatch;
          while ((tmMatch = tmRegex.exec(textStr)) !== null) {
            const senderId = tmMatch[1];
            const summary = tmMatch[2] || '';
            const body = tmMatch[3].trim();

            // Skip JSON payloads (idle_notification, shutdown, system messages)
            if (body.startsWith('{') || body.startsWith('[')) continue;
            // Skip empty bodies
            if (!body || body.length < 3) continue;
            // Skip if sender is "system"
            if (senderId === 'system') continue;

            const senderName = agentMap[senderId] || senderId;
            events.push({
              type: 'agent_message',
              timestamp: entry.timestamp || 0,
              actor: senderName,
              target: 'team-lead',
              direction: `${senderName} → team-lead`,
              summary: body.length > 500 ? body.substring(0, 500) + '...' : body,
              detail: body,
              source: 'lead_transcript',
            });
          }

          // Parse <idle_notification> tags (for peer DM summaries)
          const idleRegex = /<idle_notification\s+[^>]*?agent_id="([^"]+)"[^>]*?(?:peer_dm_summary="([^"]*)")?[^>]*/g;
          let idleMatch;
          while ((idleMatch = idleRegex.exec(textStr)) !== null) {
            const agentId = idleMatch[1];
            const peerSummary = idleMatch[2];
            const aName = agentMap[agentId] || agentId;
            if (peerSummary && peerSummary.length > 5) {
              events.push({
                type: 'peer_dm',
                timestamp: entry.timestamp || 0,
                actor: aName,
                target: null,
                summary: peerSummary,
                detail: '',
                source: 'lead_transcript',
              });
            }
          }

          // Also extract lead's own SendMessage tool_use (messages FROM lead TO agents)
          const contentBlocks = entry.content || (entry.message && entry.message.content) || [];
          if (Array.isArray(contentBlocks)) {
            for (const block of contentBlocks) {
              if (block.type === 'tool_use' && block.name === 'SendMessage' && block.input) {
                const inp = block.input;
                // Skip shutdown/system messages
                if (inp.type === 'shutdown_request' || inp.type === 'shutdown_response') continue;
                if (inp.type === 'message' && inp.content && inp.recipient) {
                  // Skip JSON payloads and shutdown requests
                  if (inp.content.startsWith('{') || inp.content.startsWith('[')) continue;
                  events.push({
                    type: 'agent_message',
                    timestamp: entry.timestamp || 0,
                    actor: 'team-lead',
                    target: inp.recipient,
                    direction: `team-lead → ${inp.recipient}`,
                    summary: inp.content.length > 500 ? inp.content.substring(0, 500) + '...' : inp.content,
                    detail: inp.content,
                    source: 'lead_transcript',
                  });
                } else if (inp.type === 'broadcast' && inp.content) {
                  events.push({
                    type: 'broadcast',
                    timestamp: entry.timestamp || 0,
                    actor: 'team-lead',
                    target: 'all',
                    direction: 'team-lead → all',
                    summary: inp.content.length > 500 ? inp.content.substring(0, 500) + '...' : inp.content,
                    detail: inp.content,
                    source: 'lead_transcript',
                  });
                }
              }
            }
          }
        } catch (e) { /* skip malformed lines */ }
      }
    } catch (e) {
      console.error(`[TRANSCRIPT] Failed to read lead JSONL: ${e.message}`);
    }
  }

  return events;
}

/**
 * Find the lead session JSONL file path.
 * Works for both in-process teammates (no session subdir) and PTY-based ones.
 */
function findLeadJsonl(config) {
  const leadSessionId = config.leadSessionId;
  if (!leadSessionId) return null;

  const projectsDir = path.join(os.homedir(), '.claude', 'projects');
  if (!fs.existsSync(projectsDir)) return null;

  try {
    const projectDirs = fs.readdirSync(projectsDir, { withFileTypes: true }).filter(d => d.isDirectory());
    for (const pDir of projectDirs) {
      const candidate = path.join(projectsDir, pDir.name, leadSessionId + '.jsonl');
      if (fs.existsSync(candidate)) {
        return candidate;
      }
    }
  } catch (e) {
    console.error(`[TRANSCRIPT] Failed to find lead JSONL: ${e.message}`);
  }
  return null;
}

function aggregateTeamEvents(teamName) {
  const events = [];
  const messages = readTeamMessages(teamName);
  const tasks = readTeamTasks(teamName);

  // Convert inbox messages to events (filter out JSON payloads and system messages)
  for (const msg of messages) {
    const ts = typeof msg.timestamp === 'string' ? new Date(msg.timestamp).getTime() : msg.timestamp;
    let type = msg.type || 'message';

    // Skip system protocol messages (JSON payloads like idle_notification, shutdown, etc.)
    const text = msg.text || '';
    const trimmed = text.trim();
    if (trimmed.startsWith('{') || trimmed.startsWith('[')) continue;

    // Skip shutdown/system protocol types
    if (type === 'shutdown_request' || type === 'shutdown_response' || type === 'shutdown_approved') continue;
    if (type === 'idle_notification') continue;

    if (msg.from === 'viewer') type = 'boss_message';
    else if (type === 'plan_approval_request') type = 'plan_approval';

    const direction = (msg.from || 'unknown') + ' → ' + (msg.to || '?');
    events.push({
      type,
      timestamp: msg.timestamp,
      actor: msg.from || 'unknown',
      target: msg.to || null,
      direction,
      summary: text.length > 500 ? text.substring(0, 500) + '...' : text,
      detail: text,
      source: 'inbox',
    });
  }

  // Convert tasks to events (infer from status) — fallback if no transcript data
  for (const task of tasks) {
    const id = task.id || '?';
    const subject = task.subject || '(no subject)';
    const owner = task.owner || 'team-lead';

    if (task.status === 'in_progress') {
      events.push({
        type: 'task_started',
        timestamp: task.updatedAt || task.createdAt || 0,
        actor: owner,
        target: null,
        summary: `Started task #${id}: ${subject}`,
        detail: task.description || '',
        taskId: id,
        source: 'task_file',
      });
    }

    if (task.status === 'completed') {
      events.push({
        type: 'task_completed',
        timestamp: task.updatedAt || task.completedAt || task.createdAt || 0,
        actor: owner,
        target: null,
        summary: `Completed task #${id}: ${subject}`,
        detail: task.description || '',
        taskId: id,
        source: 'task_file',
      });
    }
  }

  // Mine JSONL transcripts for rich activity data
  const transcriptEvents = extractTranscriptEvents(teamName);
  events.push(...transcriptEvents);

  // Deduplicate: prefer transcript events over inbox/task_file events
  // Build a set of transcript-sourced message signatures for dedup
  const transcriptTaskEvents = new Set();
  const transcriptMsgKeys = new Set();
  for (const ev of events) {
    if (ev.source === 'transcript' || ev.source === 'lead_transcript') {
      if (ev.type === 'task_started' || ev.type === 'task_completed') {
        transcriptTaskEvents.add(ev.type + ':' + (ev.summary.match(/#(\d+)/) || ['', ''])[1]);
      }
      if (ev.type === 'agent_message' || ev.type === 'broadcast') {
        // Key: actor + first 80 chars of summary
        transcriptMsgKeys.add(ev.actor + ':' + (ev.summary || '').substring(0, 80));
      }
    }
  }

  const deduped = events.filter(ev => {
    // Remove task_file events that have transcript equivalents
    if (ev.source === 'task_file' && transcriptTaskEvents.size > 0) {
      const key = ev.type + ':' + (ev.taskId || '');
      if (transcriptTaskEvents.has(key)) return false;
    }
    // Remove inbox messages that duplicate transcript agent_messages
    if (ev.source === 'inbox' && (ev.type === 'message' || ev.type === 'broadcast')) {
      const key = ev.actor + ':' + (ev.summary || '').substring(0, 80);
      if (transcriptMsgKeys.has(key)) return false;
    }
    return true;
  });

  // Also deduplicate agent_message from lead_transcript vs transcript (same message captured twice)
  const seen = new Set();
  const finalEvents = [];
  for (const ev of deduped) {
    if (ev.type === 'agent_message' || ev.type === 'broadcast') {
      // Create a dedup key based on actor + first 80 chars of summary
      const key = ev.actor + ':' + (ev.summary || '').substring(0, 80);
      if (seen.has(key)) continue;
      seen.add(key);
    }
    finalEvents.push(ev);
  }

  // Sort by timestamp
  finalEvents.sort((a, b) => {
    const ta = typeof a.timestamp === 'string' ? new Date(a.timestamp).getTime() : (a.timestamp || 0);
    const tb = typeof b.timestamp === 'string' ? new Date(b.timestamp).getTime() : (b.timestamp || 0);
    return ta - tb;
  });

  return finalEvents;
}

// ─── Team Member Liveness Detection ──────────────────────────────────────────

const LIVENESS_TIMEOUT_MS = 5 * 60 * 1000; // 5 minutes

function getTeamMemberLiveness(teamName, config) {
  const result = {};
  const leadSessionId = config.leadSessionId;
  if (!leadSessionId) {
    // No session ID — all members are offline
    for (const m of (config.members || [])) {
      result[m.name || m.agentId] = { isAlive: false, lastActiveAt: null };
    }
    return result;
  }

  const projectsDir = path.join(os.homedir(), '.claude', 'projects');
  let sessionDir = null;

  // Find session directory
  if (fs.existsSync(projectsDir)) {
    const projectDirs = fs.readdirSync(projectsDir, { withFileTypes: true }).filter(d => d.isDirectory());
    for (const pDir of projectDirs) {
      const candidate = path.join(projectsDir, pDir.name, leadSessionId);
      if (fs.existsSync(candidate)) {
        sessionDir = candidate;
        break;
      }
    }
  }

  if (!sessionDir) {
    for (const m of (config.members || [])) {
      result[m.name || m.agentId] = { isAlive: false, lastActiveAt: null };
    }
    return result;
  }

  // Check lead session jsonl mtime
  let leadMtime = null;
  try {
    const leadJsonl = path.join(sessionDir, '..', leadSessionId + '.jsonl');
    if (fs.existsSync(leadJsonl)) {
      leadMtime = fs.statSync(leadJsonl).mtimeMs;
    }
  } catch (e) { /* ignore */ }

  // Also check files inside session dir
  if (!leadMtime) {
    try {
      const files = fs.readdirSync(sessionDir).filter(f => f.endsWith('.jsonl'));
      for (const f of files) {
        const mt = fs.statSync(path.join(sessionDir, f)).mtimeMs;
        if (!leadMtime || mt > leadMtime) leadMtime = mt;
      }
    } catch (e) { /* ignore */ }
  }

  const now = Date.now();
  const leadAlive = leadMtime ? (now - leadMtime < LIVENESS_TIMEOUT_MS) : false;

  // Check subagent jsonls
  const subagentsDir = path.join(sessionDir, 'subagents');
  const subagentMtimes = {};
  if (fs.existsSync(subagentsDir)) {
    try {
      const files = fs.readdirSync(subagentsDir).filter(f => f.endsWith('.jsonl'));
      for (const f of files) {
        const mt = fs.statSync(path.join(subagentsDir, f)).mtimeMs;
        subagentMtimes[f] = mt;
      }
    } catch (e) { /* ignore */ }
  }

  for (const m of (config.members || [])) {
    const name = m.name || m.agentId;
    const agentId = m.agentId;

    // Try to match subagent file
    let memberMtime = null;
    for (const [file, mt] of Object.entries(subagentMtimes)) {
      if (file.includes(agentId) || file.includes(name)) {
        memberMtime = mt;
        break;
      }
    }

    // Use lead mtime as fallback (lead agent encompasses all)
    const bestMtime = memberMtime || leadMtime;
    const isAlive = bestMtime ? (now - bestMtime < LIVENESS_TIMEOUT_MS) : false;

    result[name] = {
      isAlive: leadAlive || isAlive,
      lastActiveAt: bestMtime || null,
    };
  }

  return result;
}

function findLeadSessionDir(config) {
  const leadSessionId = config.leadSessionId;
  if (!leadSessionId) return null;

  const projectsDir = path.join(os.homedir(), '.claude', 'projects');
  if (!fs.existsSync(projectsDir)) return null;

  const projectDirs = fs.readdirSync(projectsDir, { withFileTypes: true }).filter(d => d.isDirectory());
  for (const pDir of projectDirs) {
    const candidate = path.join(projectsDir, pDir.name, leadSessionId);
    if (fs.existsSync(candidate)) {
      return { sessionDir: candidate, projectDir: path.join(projectsDir, pDir.name) };
    }
  }
  return null;
}

// ─── API Routes ──────────────────────────────────────────────────────────────

app.get('/api/recent-projects', (req, res) => {
  try {
    const seen = new Map();
    for (const agent of Object.values(registry)) {
      if (agent.projectPath) {
        const existing = seen.get(agent.projectPath) || 0;
        const ts = agent.createdAt || 0;
        if (ts > existing) seen.set(agent.projectPath, ts);
      }
    }
    const sorted = [...seen.entries()]
      .sort((a, b) => b[1] - a[1])
      .map(([p]) => p);
    res.json(sorted);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.get('/api/agents', (req, res) => {
  try {
    res.json(getAllAgents());
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.post('/api/agents', async (req, res) => {
  try {
    const { projectPath, prompt } = req.body;
    if (!projectPath || !prompt) {
      return res.status(400).json({ error: 'projectPath and prompt are required' });
    }
    const name = await spawnAgent(projectPath, prompt);
    res.json({ name, status: 'spawned' });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.post('/api/agents/:name/send', (req, res) => {
  try {
    const { name } = req.params;
    const { message } = req.body;
    if (!message) {
      return res.status(400).json({ error: 'message is required' });
    }

    const reg = registry[name];

    // If agent is completed/dead, re-spawn it in the same project
    if (reg && reg.state === 'completed') {
      const projectPath = reg.projectPath || '.';
      const claudeCmd = 'claude --dangerously-skip-permissions';

      createSession(name, projectPath, claudeCmd);

      reg.state = 'running';
      reg.prompt = message;
      delete reg.idleSince;
      delete reg.completedAt;
      saveRegistry();

      waitForClaudeReady(name).then(ready => {
        if (!ready) {
          console.log(`[RESPAWN] Claude not ready for ${name}, sending prompt anyway`);
        }
        sendToAgent(name, message);
      });

      return res.json({ status: 'respawned' });
    }

    // Otherwise send to live session
    const success = sendToAgent(name, message);
    if (success) {
      if (reg) {
        reg.state = 'running';
        reg.lastMessageSentAt = Date.now();
        delete reg.idleSince;
        saveRegistry();
      }
      res.json({ status: 'sent' });
    } else {
      res.status(500).json({ error: 'Failed to send message' });
    }
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// File upload - save locally and send path to agent
const UPLOAD_DIR = path.join(os.tmpdir(), 'agent-viewer-uploads');

app.post('/api/agents/:name/upload', (req, res) => {
  try {
    const { name } = req.params;

    const chunks = [];
    req.on('data', chunk => chunks.push(chunk));
    req.on('end', () => {
      try {
        const buf = Buffer.concat(chunks);
        const contentType = req.headers['content-type'] || '';

        const boundaryMatch = contentType.match(/boundary=(.+)/);
        if (!boundaryMatch) {
          return res.status(400).json({ error: 'Invalid multipart form' });
        }
        const boundary = boundaryMatch[1];
        const bodyStr = buf.toString('latin1');

        const filenameMatch = bodyStr.match(/filename="([^"]+)"/);
        const filename = filenameMatch ? filenameMatch[1] : 'upload-' + Date.now();

        const headerEnd = bodyStr.indexOf('\r\n\r\n');
        const fileStart = headerEnd + 4;
        const fileEnd = bodyStr.lastIndexOf('\r\n--' + boundary);
        const fileBytes = buf.slice(
          Buffer.byteLength(bodyStr.substring(0, fileStart), 'latin1'),
          Buffer.byteLength(bodyStr.substring(0, fileEnd), 'latin1')
        );

        if (!fs.existsSync(UPLOAD_DIR)) fs.mkdirSync(UPLOAD_DIR, { recursive: true });
        const savePath = path.join(UPLOAD_DIR, `${Date.now()}-${filename}`);
        fs.writeFileSync(savePath, fileBytes);

        const isImage = /\.(png|jpg|jpeg|gif|webp|svg|bmp)$/i.test(filename);
        const msg = isImage
          ? `Look at this image and tell me what you see: ${savePath}`
          : `Read this file: ${savePath}`;

        sendToAgent(name, msg);

        if (registry[name]) {
          registry[name].state = 'running';
          delete registry[name].idleSince;
          saveRegistry();
        }

        res.json({ status: 'uploaded', path: savePath });
      } catch (e) {
        res.status(500).json({ error: e.message });
      }
    });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.delete('/api/agents/:name', (req, res) => {
  try {
    killAgent(req.params.name);
    res.json({ status: 'killed' });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.delete('/api/agents/:name/cleanup', (req, res) => {
  try {
    const { name } = req.params;
    if (!registry[name]) {
      return res.status(404).json({ error: 'Agent not found' });
    }
    if (registry[name].state !== 'completed') {
      return res.status(400).json({ error: 'Agent is not completed' });
    }
    delete registry[name];
    sessions.delete(name);
    saveRegistry();
    res.json({ status: 'cleaned' });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.delete('/api/cleanup/completed', (req, res) => {
  try {
    let count = 0;
    for (const name of Object.keys(registry)) {
      if (registry[name].state === 'completed') {
        delete registry[name];
        sessions.delete(name);
        count++;
      }
    }
    saveRegistry();
    res.json({ status: 'cleaned', count });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// Send raw keys (for interactive prompts: Up, Down, Space, Enter, Escape)
app.post('/api/agents/:name/keys', (req, res) => {
  try {
    const { name } = req.params;
    const { keys } = req.body;
    if (!keys) {
      return res.status(400).json({ error: 'keys is required' });
    }

    const allowed = ['Up', 'Down', 'Space', 'Enter', 'Escape', 'Tab'];
    if (!allowed.includes(keys)) {
      return res.status(400).json({ error: `Invalid key. Allowed: ${allowed.join(', ')}` });
    }

    const session = sessions.get(name);
    if (!session || session.dead) {
      return res.status(404).json({ error: 'Session not found' });
    }

    // Map key names to escape sequences
    const keyMap = {
      'Up': '\x1B[A',
      'Down': '\x1B[B',
      'Space': ' ',
      'Enter': '\r',
      'Escape': '\x1B',
      'Tab': '\t',
    };

    session.pty.write(keyMap[keys]);

    if (registry[name]) {
      registry[name].lastMessageSentAt = Date.now();
      saveRegistry();
    }

    res.json({ status: 'sent', key: keys });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// Send plan feedback
app.post('/api/agents/:name/plan-feedback', async (req, res) => {
  try {
    const { name } = req.params;
    const { message } = req.body;
    if (!message) {
      return res.status(400).json({ error: 'message is required' });
    }

    const session = sessions.get(name);
    if (!session || session.dead) {
      return res.status(404).json({ error: 'Session not found' });
    }

    // Read pane to find numbered options and locate "Type here" option
    const rawOutput = capturePaneOutput(name, 50);
    const output = stripAnsi(rawOutput);
    const lines = output.split('\n').map(l => l.trim()).filter(l => l !== '');
    const recentLines = lines.slice(-20);

    const optionLines = recentLines.filter(l => /^\d+[.)]\s/.test(l));
    const typeHereIdx = optionLines.findIndex(l => /type here/i.test(l));

    if (typeHereIdx < 0) {
      return res.status(400).json({ error: 'Could not find "Type here" option in plan prompt' });
    }

    // Navigate to top first
    for (let i = 0; i < optionLines.length + 2; i++) {
      session.pty.write('\x1B[A'); // Up
      await new Promise(r => setTimeout(r, 50));
    }

    // Navigate down to the "Type here" option
    for (let i = 0; i < typeHereIdx; i++) {
      session.pty.write('\x1B[B'); // Down
      await new Promise(r => setTimeout(r, 50));
    }

    // Select the option
    session.pty.write('\r');

    // Wait for the text input to appear
    await new Promise(r => setTimeout(r, 500));

    // Type the feedback
    session.pty.write(message);

    // Submit
    session.pty.write('\r');

    if (registry[name]) {
      registry[name].lastMessageSentAt = Date.now();
      saveRegistry();
    }

    console.log(`[PLAN-FEEDBACK] Sent to ${name} (option ${typeHereIdx}): ${message.substring(0, 80)}`);
    res.json({ status: 'sent', optionIndex: typeHereIdx });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.get('/api/agents/:name/output', (req, res) => {
  try {
    const raw = capturePaneOutput(req.params.name, 200);
    const clean = stripAnsi(raw);
    res.json({ output: clean, raw });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ─── Directory Browser ───────────────────────────────────────────────────────

app.get('/api/browse', (req, res) => {
  try {
    const dir = req.query.dir || os.homedir();
    const resolved = path.resolve(dir);

    if (!fs.existsSync(resolved) || !fs.statSync(resolved).isDirectory()) {
      return res.status(400).json({ error: 'Not a valid directory' });
    }

    const entries = fs.readdirSync(resolved, { withFileTypes: true });
    const dirs = entries
      .filter(e => e.isDirectory() && !e.name.startsWith('.'))
      .map(e => e.name)
      .sort((a, b) => a.localeCompare(b, undefined, { sensitivity: 'base' }));

    res.json({
      current: resolved,
      parent: path.dirname(resolved),
      dirs,
    });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ─── Team API Endpoints ──────────────────────────────────────────────────

app.get('/api/teams', (req, res) => {
  try {
    res.json(scanTeams());
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.get('/api/teams/:name', (req, res) => {
  try {
    const config = readTeamConfig(req.params.name);
    if (!config) return res.status(404).json({ error: 'Team not found' });
    res.json(config);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.get('/api/teams/:name/full', (req, res) => {
  try {
    const data = getFullTeamData(req.params.name);
    if (!data) return res.status(404).json({ error: 'Team not found' });
    res.json(data);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.get('/api/teams/:name/tasks', (req, res) => {
  try {
    res.json(readTeamTasks(req.params.name));
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.get('/api/teams/:name/messages', (req, res) => {
  try {
    res.json(readTeamMessages(req.params.name));
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.get('/api/teams/:name/messages/:agent', (req, res) => {
  try {
    res.json(readTeamMessages(req.params.name, req.params.agent));
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ─── Team Agent Interaction APIs ─────────────────────────────────────

// Send message to a team agent's inbox
app.post('/api/teams/:name/members/:agent/send', (req, res) => {
  try {
    const { name, agent } = req.params;
    const { message } = req.body;
    if (!message) return res.status(400).json({ error: 'message is required' });

    const inboxDir = path.join(TEAMS_DIR, name, 'inboxes');
    if (!fs.existsSync(inboxDir)) fs.mkdirSync(inboxDir, { recursive: true });

    const inboxFile = path.join(inboxDir, `${agent}.json`);
    let inbox = [];
    try {
      if (fs.existsSync(inboxFile)) {
        const data = JSON.parse(fs.readFileSync(inboxFile, 'utf-8'));
        inbox = Array.isArray(data) ? data : (data.messages || []);
      }
    } catch (e) { /* start fresh */ }

    inbox.push({
      from: 'viewer',
      text: message,
      timestamp: new Date().toISOString(),
      read: false,
      type: 'message',
    });

    fs.writeFileSync(inboxFile, JSON.stringify(inbox, null, 2));
    res.json({ status: 'sent' });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// Send shutdown request to a team agent
app.post('/api/teams/:name/members/:agent/shutdown', (req, res) => {
  try {
    const { name, agent } = req.params;

    const inboxDir = path.join(TEAMS_DIR, name, 'inboxes');
    if (!fs.existsSync(inboxDir)) fs.mkdirSync(inboxDir, { recursive: true });

    const inboxFile = path.join(inboxDir, `${agent}.json`);
    let inbox = [];
    try {
      if (fs.existsSync(inboxFile)) {
        const data = JSON.parse(fs.readFileSync(inboxFile, 'utf-8'));
        inbox = Array.isArray(data) ? data : (data.messages || []);
      }
    } catch (e) { /* start fresh */ }

    inbox.push({
      from: 'viewer',
      type: 'shutdown_request',
      text: 'Shutdown requested from Agent Viewer',
      timestamp: new Date().toISOString(),
      read: false,
      requestId: `shutdown-${Date.now()}`,
    });

    fs.writeFileSync(inboxFile, JSON.stringify(inbox, null, 2));
    res.json({ status: 'shutdown_requested' });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// Wake a team agent (resume lead session or start fresh)
app.post('/api/teams/:name/wake', async (req, res) => {
  try {
    const { name } = req.params;
    const { mode, targetAgent } = req.body;

    const config = readTeamConfig(name);
    if (!config) return res.status(404).json({ error: 'Team not found' });

    const teamCwd = config.cwd || config.workingDirectory || os.homedir();

    if (mode === 'resume') {
      // Resume lead session
      const leadSessionId = config.leadSessionId;
      if (!leadSessionId) return res.status(400).json({ error: 'No leadSessionId in team config' });

      const sessionName = `team-${name}-lead-${Date.now().toString(36).slice(-4)}`;
      const claudeCmd = `claude --resume ${leadSessionId} --dangerously-skip-permissions`;

      console.log(`[WAKE] Resuming lead session for team ${name}: ${claudeCmd}`);
      createSession(sessionName, teamCwd, claudeCmd);

      // Register in agent-viewer registry
      registry[sessionName] = {
        label: `${name}-lead-resumed`,
        projectPath: teamCwd,
        prompt: `Resumed lead session for team "${name}"`,
        createdAt: Date.now(),
        state: 'running',
        initialPromptSent: true,
        teamWake: { teamName: name, mode: 'resume', leadSessionId },
      };
      saveRegistry();

      res.json({ status: 'waking', sessionName, mode: 'resume' });
    } else if (mode === 'fresh') {
      // Start fresh agent for a specific member
      if (!targetAgent) return res.status(400).json({ error: 'targetAgent is required for fresh mode' });

      const member = (config.members || []).find(m => (m.name || m.agentId) === targetAgent);
      if (!member) return res.status(404).json({ error: 'Member not found' });

      const sessionName = `team-${name}-${targetAgent}-${Date.now().toString(36).slice(-4)}`;
      const claudeCmd = 'claude --dangerously-skip-permissions';

      console.log(`[WAKE] Starting fresh agent for ${targetAgent} in team ${name}`);
      createSession(sessionName, teamCwd, claudeCmd);

      // Build a prompt from member's role + unread inbox messages
      const messages = readTeamMessages(name, targetAgent);
      const unread = messages.filter(m => !m.read);
      let prompt = `You are "${targetAgent}" in team "${name}".`;
      if (member.prompt) prompt += `\n\nYour role: ${member.prompt}`;
      if (unread.length > 0) {
        prompt += `\n\nYou have ${unread.length} unread messages:\n`;
        for (const msg of unread.slice(-5)) {
          prompt += `- From ${msg.from}: ${msg.text}\n`;
        }
      }
      prompt += '\n\nPlease check your team task list and continue working.';

      registry[sessionName] = {
        label: `${name}-${targetAgent}-fresh`,
        projectPath: teamCwd,
        prompt,
        createdAt: Date.now(),
        state: 'running',
        initialPromptSent: false,
        teamWake: { teamName: name, mode: 'fresh', targetAgent },
      };
      saveRegistry();

      // Send prompt after Claude is ready
      waitForClaudeReady(sessionName).then(ready => {
        if (!ready) console.log(`[WAKE] Claude not ready for ${sessionName}, sending anyway`);
        sendToAgent(sessionName, prompt);
        if (registry[sessionName]) {
          registry[sessionName].initialPromptSent = true;
          saveRegistry();
        }
      });

      res.json({ status: 'waking', sessionName, mode: 'fresh' });
    } else {
      return res.status(400).json({ error: 'mode must be "resume" or "fresh"' });
    }
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// Read agent transcript (conversation history from .jsonl)
app.get('/api/teams/:name/members/:agent/transcript', (req, res) => {
  try {
    const { name, agent } = req.params;
    const tail = parseInt(req.query.tail) || 0;

    const config = readTeamConfig(name);
    if (!config) return res.status(404).json({ error: 'Team not found' });

    const leadSessionId = config.leadSessionId;
    if (!leadSessionId) return res.json({ messages: [], error: 'No leadSessionId in config' });

    // Find the member to get agentId
    const member = (config.members || []).find(m => m.name === agent);
    if (!member) return res.status(404).json({ error: 'Member not found' });

    const agentId = member.agentId;

    // Locate the project directory for .claude/projects mapping
    // Try to find the session in ~/.claude/projects/
    const projectsDir = path.join(os.homedir(), '.claude', 'projects');
    let transcriptPath = null;

    if (fs.existsSync(projectsDir)) {
      const projectDirs = fs.readdirSync(projectsDir, { withFileTypes: true })
        .filter(d => d.isDirectory());

      for (const pDir of projectDirs) {
        // Check for session directory
        const sessionDir = path.join(projectsDir, pDir.name, leadSessionId);
        if (fs.existsSync(sessionDir)) {
          // Look for subagent .jsonl files
          const subagentsDir = path.join(sessionDir, 'subagents');
          if (fs.existsSync(subagentsDir)) {
            const jsonlFiles = fs.readdirSync(subagentsDir).filter(f => f.endsWith('.jsonl'));
            // Match by agentId in filename or by reading first line
            // agentId format: "architect@daily-tracker", filename: "agent-{hash}.jsonl"
            let match = jsonlFiles.find(f => f.includes(agentId));
            if (!match) {
              // Try matching by reading the first line of each file to find the agent
              for (const jf of jsonlFiles) {
                try {
                  const fp = path.join(subagentsDir, jf);
                  const firstLine = fs.readFileSync(fp, 'utf-8').split('\n')[0];
                  const entry = JSON.parse(firstLine);
                  // Check if the content mentions this agent name
                  const content = JSON.stringify(entry);
                  if (content.includes(`"${agent}"`) || content.includes(`teammate_id=\\"${agent}\\"`)) {
                    match = jf;
                    break;
                  }
                } catch (e) { /* skip */ }
              }
            }
            // If only one subagent and one non-lead member, match directly
            if (!match && jsonlFiles.length === 1 && (config.members || []).filter(m => m.name !== 'team-lead').length === 1) {
              match = jsonlFiles[0];
            }
            if (match) {
              transcriptPath = path.join(subagentsDir, match);
              break;
            }
          }
          // Also check directly in session dir
          const sessionFiles = fs.readdirSync(sessionDir).filter(f => f.endsWith('.jsonl'));
          const match = sessionFiles.find(f => f.includes(agentId));
          if (match) {
            transcriptPath = path.join(sessionDir, match);
            break;
          }
        }
      }
    }

    if (!transcriptPath) {
      return res.json({ messages: [], info: 'Transcript file not found' });
    }

    // Parse JSONL
    const content = fs.readFileSync(transcriptPath, 'utf-8');
    const lines = content.split('\n').filter(l => l.trim());
    let entries = [];
    for (const line of lines) {
      try {
        entries.push(JSON.parse(line));
      } catch (e) { /* skip malformed */ }
    }

    // Extract meaningful messages
    const messages = [];
    for (const entry of entries) {
      const entryType = entry.type || '';
      const msgRole = entry.message?.role || entry.role || '';

      if (entryType === 'user' || msgRole === 'user') {
        const text = extractText(entry);
        // For tool_result entries, extract from content blocks
        const toolResults = extractToolResults(entry);
        if (text) {
          messages.push({ role: 'user', text, timestamp: entry.timestamp });
        } else if (toolResults) {
          messages.push({ role: 'tool', text: toolResults.substring(0, 500), timestamp: entry.timestamp });
        }
      } else if (entryType === 'assistant' || msgRole === 'assistant') {
        const text = extractText(entry);
        const toolUse = extractToolUse(entry);
        if (text || toolUse) messages.push({ role: 'assistant', text: text || '', toolUse, timestamp: entry.timestamp });
      }
    }

    // Apply tail filter
    const result = tail > 0 ? messages.slice(-tail) : messages;

    // Extract usage data
    let totalInputTokens = 0, totalOutputTokens = 0;
    for (const entry of entries) {
      if (entry.usage) {
        totalInputTokens += entry.usage.input_tokens || 0;
        totalOutputTokens += entry.usage.output_tokens || 0;
      }
    }

    res.json({
      messages: result,
      totalMessages: messages.length,
      usage: { inputTokens: totalInputTokens, outputTokens: totalOutputTokens },
      transcriptPath,
    });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

function extractText(entry) {
  if (typeof entry.content === 'string') return entry.content;
  if (typeof entry.text === 'string') return entry.text;
  if (typeof entry.message === 'string') return entry.message;
  if (Array.isArray(entry.content)) {
    return entry.content
      .filter(b => b.type === 'text')
      .map(b => b.text)
      .join('\n');
  }
  if (entry.message && typeof entry.message.content === 'string') return entry.message.content;
  if (entry.message && Array.isArray(entry.message.content)) {
    return entry.message.content
      .filter(b => b.type === 'text')
      .map(b => b.text)
      .join('\n');
  }
  return '';
}

function extractToolResults(entry) {
  const content = entry.content || (entry.message && entry.message.content) || [];
  if (!Array.isArray(content)) return '';
  const results = content.filter(b => b.type === 'tool_result');
  if (results.length === 0) return '';
  return results.map(r => {
    if (typeof r.content === 'string') return r.content;
    if (Array.isArray(r.content)) return r.content.filter(b => b.type === 'text').map(b => b.text).join('\n');
    return '';
  }).filter(Boolean).join('\n');
}

function extractToolUse(entry) {
  const content = entry.content || (entry.message && entry.message.content) || [];
  if (!Array.isArray(content)) return null;
  const tools = content.filter(b => b.type === 'tool_use');
  if (tools.length === 0) return null;
  return tools.map(t => ({ name: t.name, input: t.input ? JSON.stringify(t.input).substring(0, 200) : '' }));
}

// Update a team task
app.post('/api/teams/:name/tasks/:id', (req, res) => {
  try {
    const { name, id } = req.params;
    const { status, owner } = req.body;

    const tasksDir = path.join(TASKS_DIR, name);
    if (!fs.existsSync(tasksDir)) return res.status(404).json({ error: 'Task directory not found' });

    // Find task file
    const files = fs.readdirSync(tasksDir).filter(f => f.endsWith('.json'));
    let taskFile = null;
    let taskData = null;

    for (const file of files) {
      try {
        const data = JSON.parse(fs.readFileSync(path.join(tasksDir, file), 'utf-8'));
        if (String(data.id) === String(id)) {
          taskFile = path.join(tasksDir, file);
          taskData = data;
          break;
        }
      } catch (e) { /* skip */ }
    }

    if (!taskFile || !taskData) return res.status(404).json({ error: 'Task not found' });

    if (status) taskData.status = status;
    if (owner !== undefined) taskData.owner = owner;

    fs.writeFileSync(taskFile, JSON.stringify(taskData, null, 2));
    res.json({ status: 'updated', task: taskData });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ─── SSE Endpoint ────────────────────────────────────────────────────────────

const sseClients = new Set();

app.get('/api/events', (req, res) => {
  res.writeHead(200, {
    'Content-Type': 'text/event-stream',
    'Cache-Control': 'no-cache',
    Connection: 'keep-alive',
  });

  res.write('data: {"type":"connected"}\n\n');
  sseClients.add(res);

  req.on('close', () => {
    sseClients.delete(res);
  });
});

function broadcastAgents() {
  if (sseClients.size === 0) return;
  try {
    const agents = getAllAgents();
    const data = JSON.stringify({ type: 'agents', agents });
    for (const client of sseClients) {
      client.write(`data: ${data}\n\n`);
    }
  } catch (e) {
    console.error('SSE broadcast error:', e.message);
  }
}

function broadcastTeams() {
  if (sseClients.size === 0) return;
  try {
    const teamsList = scanTeams();
    const teamsData = {};
    for (const team of teamsList) {
      teamsData[team.name] = getFullTeamData(team.name);
    }
    const data = JSON.stringify({ type: 'teams', teams: teamsList, teamsData });
    for (const client of sseClients) {
      client.write(`data: ${data}\n\n`);
    }
  } catch (e) {
    console.error('SSE teams broadcast error:', e.message);
  }
}

function broadcastAll() {
  broadcastAgents();
  broadcastTeams();
}

// ─── Server Start ────────────────────────────────────────────────────────────

loadRegistry();

// Mark all pre-existing registry entries as completed on startup
// (since in-memory PTY sessions don't survive restart)
for (const name of Object.keys(registry)) {
  if (registry[name].state !== 'completed') {
    registry[name].state = 'completed';
    registry[name].completedAt = registry[name].completedAt || Date.now();
  }
}
saveRegistry();

app.listen(PORT, HOST === 'localhost' ? '127.0.0.1' : HOST, () => {
  console.log(`\n  AGENT VIEWER`);
  console.log(`  ════════════════════════════════`);
  console.log(`  Local:   http://localhost:${PORT}`);

  if (HOST === '0.0.0.0') {
    const interfaces = os.networkInterfaces();
    for (const iface of Object.values(interfaces)) {
      for (const addr of iface) {
        if (addr.family === 'IPv4' && !addr.internal) {
          console.log(`  Network: http://${addr.address}:${PORT}`);
        }
      }
    }
  }

  console.log(`  ════════════════════════════════\n`);
});

setInterval(broadcastAll, POLL_INTERVAL);
