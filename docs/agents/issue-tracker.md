# Issue Tracker: Local Markdown

Issues are tracked as markdown files under `.scratch/<feature>/issues/` in this repository.

## Creating Issues

1. Create a directory for the feature: `mkdir -p .scratch/<feature-name>/issues`
2. Create an issue file: `ISSUE-<number>-<short-description>.md`
3. Use this template:

```markdown
---
id: ISSUE-<number>
title: <Issue Title>
status: open
category: bug
triage_state: needs-triage
priority: medium
---

## Description

<Detailed description of the issue>

## Acceptance Criteria

- [ ] Criterion 1
- [ ] Criterion 2

## Technical Notes

<Implementation details, constraints, or considerations>
```

## Issue Status Values

- `open`: Ready for implementation
- `in-progress`: Currently being worked on
- `done`: Completed and merged
- `blocked`: Cannot proceed due to dependencies
- `wontfix`: Decided not to implement

## Triage Fields

`status` beschreibt den Arbeitsstand. Die Triage-Rollen stehen daneben, damit
Triage und Arbeitsstand getrennt geführt werden können:

- `category`: `bug` (etwas ist kaputt) oder `enhancement` (neue Fähigkeit)
- `triage_state`: `needs-triage`, `needs-info`, `ready-for-agent`,
  `ready-for-human`, `wontfix` oder `erledigt`
- `agent_brief`: Pfad zum Agent-Brief unter `.scratch/<feature>/briefs/`,
  gesetzt sobald `triage_state` auf `ready-for-agent` steht

Ein `ready-for-agent`-Issue trägt zusätzlich einen Abschnitt `## Triage Notes`
mit dem Verifikationsstand und einen `## Agent Brief` mit Verweis auf die
Brief-Datei. Der Brief ist die verbindliche Spezifikation für einen AFK-Agenten;
Description und Triage Notes sind Kontext.

## Working with Issues

Skills like `/to-tickets`, `/implement`, and `/code-review` will:
- Read issue files to understand requirements
- Update status as work progresses
- Reference issue IDs in commits and PRs

## Best Practices

- Keep issue descriptions focused and specific
- Use clear, actionable acceptance criteria
- Link related issues using `Related: ISSUE-<number>`
- Update technical notes with implementation insights
