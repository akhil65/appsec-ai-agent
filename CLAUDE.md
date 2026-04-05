# CLAUDE.md - AI Coding Assistant Configuration

**Purpose**: This document is the primary source of context for all AI tools working on this project. It dictates how Claude (and other AI assistants) should behave within this repository.

---

## Project Nature

This is an **AppSec Remediation Agent** - a security automation system that:
- Detects security vulnerabilities (from SAST scanners)
- Deduplicates findings across tools
- Generates remediation plans
- Creates fixes automatically
- Validates fixes with tests
- Creates PRs for developer review

**Critical**: All security findings must be fixed. Do NOT preserve or introduce vulnerabilities for any reason.

---

## How AI Tools Should Work Here

### ✅ Good Use Cases for Claude/Copilot

1. **Code Analysis**
   - Understand existing code structure
   - Identify patterns and dependencies
   - Analyze vulnerability patterns

2. **Remediation Generation**
   - Generate fixes for security vulnerabilities
   - Follow policy-driven approach (read `src/policies/*.md`)
   - Create secure code patterns

3. **Test Writing**
   - Create unit tests for security fixes
   - Write integration tests
   - Create security-specific tests (injection payloads, etc.)

4. **Bug Fixing**
   - Fix bugs in the remediation agent itself
   - Improve agent logic
   - Resolve issues found in testing

5. **Documentation**
   - Write clear comments explaining security fixes
   - Document policy decisions
   - Update README and guides

6. **Agent Development**
   - Build new agents (Dedup Agent, Plan Agent, etc.)
   - Improve existing agent logic
   - Add new capabilities

### ⚠️ Use With Caution

1. **Dependency Updates**
   - Verify any suggested package updates
   - Run tests after dependency changes
   - Check for security implications

2. **Policy Modifications**
   - Only modify policies with security team review
   - Ensure changes align with org standards
   - Update policy version numbers

3. **External Integrations**
   - Consult before adding new SAST scanners
   - Verify API security
   - Document integration requirements

### ❌ Do NOT

1. **Preserve Vulnerabilities**
   - All security findings must be remediated
   - Do NOT create intentional vulnerabilities
   - Do NOT suggest unsafe code patterns
   - Do NOT comment out security controls

2. **Skip Validations**
   - Always run tests after changes
   - Always validate fixes with SAST re-scan
   - Always verify evidence capture
   - Always follow policy requirements

3. **Bypass Governance**
   - Do NOT skip approval workflows
   - Do NOT ignore confidence thresholds
   - Do NOT bypass guardrails
   - Do NOT skip evidence logging

4. **Generate Noise**
   - Remove unnecessary comments
   - Keep code clean and focused
   - Don't add debug statements
   - Clean up AI-generated placeholders

---

## Key Files & Their Purpose

### Architecture Files
- `docs/06_SYSTEM_ARCHITECTURE.md` - Overall system design
- `docs/WEEK_1_EXPLAINED.md` - Foundation components
- `docs/GOVERNANCE_CHECKLIST.md` - What's covered

### Implementation Guides
- `docs/05_QUICK_START_GUIDE.md` - Getting started
- `docs/04_PHASE_1_IMPLEMENTATION_ROADMAP.md` - Phase 1 tasks
- `docs/WEEK_1.5_EXTENDED_COMPLETE_GUIDE.md` - Complete Week 1.5

### Source Code

**Models** (`src/models/`):
- `finding.py` - SAST scan results
- `vulnerability.py` - CWE patterns
- `workplan.py` - Remediation plans
- `remediation.py` - Fix outcomes

**Services** (`src/services/`):
- `policy_engine.py` - Reads/enforces policies
- `vector_db.py` - Duplicate detection
- `governance_logger.py` - Evidence capture
- `guardrails.py` - Policy enforcement

**Agents** (`src/agents/`):
- `plan_agent.py` - Generates remediation plans
- `dedup_agent.py` - Detects duplicates
- `remediation_agent.py` - Generates fixes

**Policies** (`src/policies/`):
- `_template.md` - Policy structure template
- `cwe_*.md` - Vulnerability-specific policies
  - `cwe_89_sqli.md` - SQL Injection
  - `cwe_79_xss.md` - Cross-site Scripting (create as needed)
  - etc.

**Utilities** (`src/utils/`):
- `config.py` - Configuration management
- `logging.py` - Structured logging
- `pr_markers.py` - PR labels and comments

### Tests
- `tests/unit/` - Unit tests for components
- `tests/integration/` - Integration tests
- `tests/fixtures/` - Test data

---

## How Policies Work

### Policy Files (`src/policies/cwe_*.md`)

Each policy file:
- Defines remediation tiers (1, 2, 3)
- Lists do's and don'ts
- Provides code examples
- Specifies testing requirements
- Defines approval chains

**When modifying policies**:
- Update version number
- Document why (changelog)
- Run tests to verify
- Ensure backward compatibility

### Policy Engine

The `PolicyEngine` service:
- Loads all policies from `src/policies/`
- Parses markdown files
- Provides API for agents to query policies
- Validates fixes against policies

**When adding new policies**:
1. Create `src/policies/cwe_*.md`
2. Engine automatically picks it up
3. No code changes needed
4. Document the policy in this file

---

## Guidelines for Security Fixes

### When Claude Suggests a Fix

1. **Read the policy first**
   - Check `src/policies/cwe_89_sqli.md` (example)
   - Understand Tier 1/2/3 requirements
   - Follow institutional requirements

2. **Follow the pattern**
   - Code patterns in policy are the standard
   - Don't deviate without good reason
   - Match org code style

3. **Validate the fix**
   - Does it pass the policy's detection patterns?
   - Does it comply with policy requirements?
   - Does it include tests?

4. **Create evidence**
   - Evidence should be auto-logged
   - Include confidence score
   - Link to policy version
   - Document reasoning

---

## Testing Requirements

### For Any Security Fix

1. **Run existing tests**
   - All tests must pass
   - No regressions allowed

2. **Create security tests**
   - Test that vulnerability is actually blocked
   - Example: injection payload must fail safely
   - Test should be specific to the CWE

3. **Run SAST re-scan**
   - Verify finding is cleared
   - Check for new findings
   - Document results in evidence

4. **Manual verification** (for Tier 2+)
   - Code review required
   - Security team review required
   - Approval recorded in evidence

---

## Evidence & Governance

### Automatic Evidence Capture

Every fix should have:
- **What changed**: Code diff
- **Why**: Policy applied, CWE, tier
- **Who**: Claude model version
- **When**: Timestamp
- **Confidence**: AI confidence score
- **Validation**: Tests passed, SAST passed

### Evidence Files

Located in `src/governance/evidence/`:
- `rem-*.json` - Evidence for each remediation
- Contains full audit trail
- Used for compliance reports

### PR Comments

Auto-generated with:
- AI model used
- Confidence score
- Policy applied
- Validation results
- Approval status

---

## Working With the Plan Agent

### Plan Agent (`src/agents/plan_agent.py`)

The Plan Agent:
- Uses Claude with extended thinking
- Generates detailed remediation workplans
- Reasons through implications
- Considers risks and dependencies

**When Claude is asked to generate a plan**:
1. It reads the finding
2. It reads the policy
3. It uses extended thinking to reason
4. It generates a detailed workplan
5. User reviews and approves
6. Only then execute

**Key principle**: Plan-first execution. Generate plan, review it, then execute.

---

## Workflow for Adding New Features

### Adding a New Agent

1. **Create the agent file**
   - `src/agents/new_agent.py`
   - Follow existing patterns (see `plan_agent.py`)

2. **Write unit tests**
   - `tests/unit/test_new_agent.py`
   - Test all key logic

3. **Write integration tests**
   - `tests/integration/test_new_agent.py`
   - Test with real data

4. **Document it**
   - Add to this CLAUDE.md
   - Explain what it does
   - Explain how to use it

5. **Commit**
   - Clear commit message
   - Reference any issues/requirements

### Adding a New Policy

1. **Create policy file**
   - `src/policies/cwe_*.md`
   - Follow `_template.md`
   - Include all sections

2. **Update PolicyEngine** (if needed)
   - Verify it loads correctly
   - No code changes usually needed

3. **Test the policy**
   - Run `PolicyEngine` tests
   - Verify tier determination works
   - Verify validation works

4. **Document it**
   - Add to this CLAUDE.md under "Policies"
   - Link to policy file

---

## Essential Do's and Don'ts

### DO
- ✅ Read policies before generating fixes
- ✅ Follow institutional requirements
- ✅ Run tests after any change
- ✅ Generate security tests
- ✅ Log evidence automatically
- ✅ Use plan-first execution
- ✅ Keep code clean and focused
- ✅ Document security decisions

### DON'T
- ❌ Create vulnerabilities (even "for testing")
- ❌ Skip security tests
- ❌ Ignore policy requirements
- ❌ Bypass approval workflows
- ❌ Leave debug code or placeholders
- ❌ Modify core logic without tests
- ❌ Skip evidence capture
- ❌ Suggest unsafe patterns

---

## Questions?

If Claude is unsure about something:
1. Check the architecture docs
2. Check the implementation guide
3. Ask in code comments with `# TODO: ASK_CLAUDE`
4. Default to "more secure" option if in doubt

---

## Version History

| Version | Date | Changes |
|---------|------|---------|
| 1.0 | 2026-04-02 | Initial CLAUDE.md for AppSec Agent |

