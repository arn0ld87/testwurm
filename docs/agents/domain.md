# Domain Documentation: Single-Context Layout

This repository uses a single-context domain documentation approach with all domain knowledge centralized at the repository root.

## File Locations

- **Glossary**: `GLOSSARY.md` at repository root
- **Architecture Decision Records**: `docs/adr/` directory
- **Domain Models**: Inline in code or `docs/domain-models.md`

## Consumer Rules

### When to Consult Domain Docs

1. **Before implementing new features**: Check `GLOSSARY.md` for established terminology and `docs/adr/` for architectural constraints
2. **During code review**: Verify implementation aligns with documented domain concepts and decisions
3. **When refactoring**: Ensure changes respect existing domain boundaries and architectural patterns

### How to Update Domain Docs

1. **New terms**: Add to `GLOSSARY.md` with clear definitions and usage examples
2. **Architecture decisions**: Create new ADR in `docs/adr/` following the format:
   ```
   ADR-<number>: <Decision Title>
   Status: proposed | accepted | deprecated
   Date: YYYY-MM-DD
   
   ## Context
   <Problem statement and constraints>
   
   ## Decision
   <Chosen approach and rationale>
   
   ## Consequences
   <Trade-offs and impacts>
   ```

3. **Domain model changes**: Update relevant documentation and add migration notes if needed

## Integration with Engineering Skills

- `/grill-with-docs`: Will reference `GLOSSARY.md` and ADRs during design discussions
- `/domain-modeling`: Uses these docs as source of truth for domain language
- `/codebase-design`: Consults ADRs for architectural constraints and patterns

## Maintenance

Domain documentation should be updated as part of the development process, not as an afterthought. Stale documentation is worse than no documentation.
