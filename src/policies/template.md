# CWE-{CWE_ID}: {CWE_NAME}

## Metadata
- **CWE ID**: {CWE_ID}
- **Severity**: CRITICAL | HIGH | MEDIUM
- **OWASP Category**: A03:2021 – Injection
- **Policy Version**: 1.0
- **Last Updated**: 2026-04-02

## Organizational Requirements

**What this vulnerability means for us:**
- [Your org's specific concern]
- [Business impact]
- [Compliance requirement]

## Remediation Tiers

### Tier 1: Auto-Fixable (Easy)
**Trigger**: Low-risk patterns, simple fixes
**Requirements**:
- No dependencies changed
- Existing test coverage >80%
- No architectural changes

**Code Pattern**:
```
BEFORE:
[vulnerable code example]

AFTER:
[safe code example]
```

**Testing**:
- Unit test: Injection payload must fail safely
- Regression: Existing tests must pass
- Performance: No >5% slowdown

**Approval**: Developer 1-click

---

### Tier 2: Review Required (Medium)
**Trigger**: Moderate-risk patterns, requires context understanding
**Requirements**:
- May use new libraries
- May change function signatures
- Requires code review

**Code Pattern**:
```
BEFORE:
[vulnerable code]

AFTER:
[safe code with library]
```

**Testing**:
- Unit test: Injection payload must fail
- Integration test: Verify no breaking changes
- Regression: All tests must pass

**Approval**: Code review + security team

---

### Tier 3: Architectural (Complex)
**Trigger**: High-risk patterns, require major refactoring
**Requirements**:
- Requires architecture review
- May require schema changes
- Deployment coordination needed

**Code Pattern**:
```
BEFORE:
[vulnerable code]

AFTER:
[refactored code with ORM/framework]
```

**Testing**:
- Full regression suite
- Load testing
- Staging environment validation

**Approval**: Architecture review + security + product

---

## Do's and Don'ts

### ✅ DO
- [Recommended practice 1]
- [Recommended practice 2]

### ❌ DON'T
- [Anti-pattern 1]
- [Anti-pattern 2]

---

## Detection Patterns

**Regex patterns to detect vulnerable code:**
```
Pattern 1: [regex]
Example: [code that matches]

Pattern 2: [regex]
Example: [code that matches]
```

---

## Testing Checklist

Before approving any fix:
- [ ] Existing tests pass (100%)
- [ ] New security test passes (injection blocked)
- [ ] No performance regression (<5%)
- [ ] Code style matches repo standards
- [ ] Docstrings updated

---

## Compliance & Audit

**Evidence to capture:**
- Which policy version applied
- Which tier was used
- Confidence score
- Model version (Claude Sonnet 4.6, etc.)
- Timestamp of remediation
- Approval chain

**Governance Tags**:
```
🤖 AI-Assisted Fix: claude-sonnet-4.6
📋 Policy Applied: cwe_{id}.md v1.0
📊 Confidence: 97%
✅ All tests passed
```

---

## Questions to Ask Before Applying This Policy

These questions are for HUMAN review, not the agent:
- Is the vulnerable code in a critical path?
- Are there dependent systems that might break?
- Has this code been modified recently?
- Are there known issues with this pattern?

---

## Historical Success Rate

| Tier | Success Rate | Token Cost | Confidence |
|------|--------------|-----------|-----------|
| Tier 1 | 98% | Low | High |
| Tier 2 | 92% | Medium | Medium |
| Tier 3 | 85% | High | Low |

---

## References

- [NIST CWE Link](https://cwe.mitre.org/data/definitions/{CWE_ID}.html)
- [OWASP Reference](https://owasp.org/)
- [Internal Security Standards](https://internal.company.com/security)
