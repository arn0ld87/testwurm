# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is a hacking/pentesting toolkit repository containing various security tools and utilities for authorized penetration testing and red team operations.

## Development Environment

- **Primary Language**: Python 3.10+
- **Package Management**: pip/venv
- **Testing Framework**: pytest
- **Code Quality**: black, flake8, mypy

## Common Development Commands

```bash
# Create virtual environment
python3 -m venv venv && source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Run tests
pytest tests/ -v

# Lint code
flake8 src/ --ignore=E203,E501,W503

# Type checking
mypy src/
```

## Architecture Notes

This repository follows a modular architecture where each tool is self-contained but shares common utilities. Key components include:

- **Scanner modules**: Network discovery and vulnerability scanning
- **Exploit modules**: CVE-specific exploitation techniques
- **C2 infrastructure**: Command and control communication
- **Dashboard**: Web-based monitoring interface

## Security Considerations

All tools are designed for **authorized penetration testing only**. Ensure proper authorization before use in any environment. Tools should implement:

- Clear scope boundaries to prevent accidental overreach
- Comprehensive logging for audit trails
- Kill switches for immediate termination
- Data encryption for sensitive information

## Code Organization

```
src/
├── scanner/          # Network discovery modules
├── exploits/         # CVE-specific exploitation code
├── c2/              # Command and control infrastructure
├── dashboard/        # Web UI and API
└── utils/           # Shared utilities
```

## Agent skills

### Issue tracker

Local markdown issues under `.scratch/<feature>/issues/`. See `docs/agents/issue-tracker.md`.

### Domain docs

Single-context layout with `GLOSSARY.md` and `docs/adr/` at repo root. See `docs/agents/domain.md`.
