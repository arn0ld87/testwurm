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
