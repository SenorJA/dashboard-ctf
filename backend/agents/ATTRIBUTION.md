# Attribution — AI Personas (Pack 17)

The `.md` persona files under `backend/agents/{security,testing,engineering,specialized}/`
are **vendored** from:

- **Repository:** https://github.com/msitarzewski/agency-agents
- **License:** MIT — `Copyright (c) 2025 AgentLand Contributors`
- **Upstream project:** https://agentland.dev

39 personas were curated for M.I.R.V. (a security-oriented operations console):
their frontmatter (`name`, `description`, `color`, `emoji`, `vibe`) is kept verbatim,
the Markdown bodies are loaded as the identity/system prompt material for
`/api/ai/chat` when the caller selects a persona. No functional code was taken
from the upstream repository — only the Markdown content.

Changes applied by M.I.R.V.:

- Filenames were prefixed by division (`security-`, `testing-`, `engineering-`,
  `specialized-`) so the directory itself is the division namespace.
- Bodies are truncated to `DEFAULT_PROMPT_CHARS` when composed into a prompt
  (`backend/agency_agents.py` → `build_persona_prompt()`).

## Upstream license (MIT)

```
MIT License

Copyright (c) 2025 AgentLand Contributors

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

## Custom personas

Personas created through `POST /api/personas` are written to
`.mirv/agents/` (override with `MIRV_AGENTS_WRITE_DIR`) and are **not** covered
by the upstream license — they belong to whoever created them.
