# CWE-89: SQL Injection

## Metadata
- **CWE ID**: 89
- **Severity**: CRITICAL
- **OWASP Category**: A03:2021 – Injection
- **Policy Version**: 2.1
- **Last Updated**: 2026-04-02

## Organizational Requirements

**Why this matters to us:**
- Attackers can bypass authentication (login bypass)
- Can exfiltrate all customer data
- Can modify/delete database records
- Compliance: PCI-DSS 6.5.1, OWASP Top 10 #3

**Our Standard**:
All database queries MUST use parameterized queries. No exceptions.

---

## Remediation Tiers

### Tier 1: Parameterized Queries (Auto-Fixable)
**When to use**: Simple string concatenation in SQL queries
**Time estimate**: 5 minutes

**Code Pattern**:
```
BEFORE:
query = f"SELECT * FROM users WHERE id={user_id}"
result = db.execute(query)

AFTER:
query = "SELECT * FROM users WHERE id=?"
result = db.execute(query, [user_id])
```

**Languages Supported**:
- Python (all DB libraries)
- JavaScript (all DB libraries)
- Java (all DB libraries)
- C# (all DB libraries)

**Testing**:
- Unit test: Pass injection payload, verify it's treated as literal string
- Regression: Existing tests must pass
- Performance: No slowdown (parameterized queries are same speed)

**Example Test**:
```python
def test_sql_injection_blocked():
    """Verify parameterized query blocks SQL injection"""
    injection_payload = "1' OR '1'='1"
    result = search_users(injection_payload)
    assert len(result) == 0  # Should find 0 users, not all users
```

**Approval**: Developer 1-click approve

---

### Tier 2: SafeSQL Library (Review Required)
**When to use**: Dynamic query building (complex WHERE clauses)
**Time estimate**: 20 minutes

**Code Pattern**:
```
BEFORE:
query = f"SELECT * FROM users WHERE {condition}"
result = db.execute(query)

AFTER:
from safesql import SafeSQL
query = SafeSQL("SELECT * FROM users WHERE {}", condition)
result = db.execute(query)
```

**Library**: SafeSQL 2.0+
**Why**: Handles dynamic SQL safely while maintaining readability

**Testing**:
- Unit test: Injection payloads must fail
- Integration test: Verify complex WHERE clauses work
- Regression: All tests must pass

**Approval**: Code review required

**Note**: Requires code review because custom logic may impact other queries

---

### Tier 3: ORM Migration (Architectural)
**When to use**: Complex dynamic SQL requiring major refactor
**Time estimate**: 4+ hours

**Code Pattern**:
```
BEFORE:
query = build_complex_query(filters, pagination, sorting)
result = db.execute(query)

AFTER:
from sqlalchemy import select
stmt = select(User).where(...)  # ORM handles SQL safely
result = db.execute(stmt)
```

**Frameworks**: SQLAlchemy (Python), Sequelize (JS), Hibernate (Java), EF (C#)

**Why**: ORM handles SQL injection prevention automatically

**Testing**:
- Full regression suite
- Schema validation
- Load testing (ORM has different performance profile)

**Approval**: Architecture review + security

---

## Do's and Don'ts

### ✅ DO
- Use parameterized queries with `?` or `%s` placeholders
- Pass data separately from SQL string
- Validate input length (defense in depth)
- Use ORM for complex queries
- Log query execution (for audit)

### ❌ DON'T
- Concatenate user input into SQL strings (`f"{var}"`)
- Use string escaping alone (insufficient)
- Comment out parameterization "for testing"
- Mix parameterized + concatenated queries
- Trust user input even after "validation"

---

## Detection Patterns

**Regex patterns agent uses to detect vulnerable code:**

```
Pattern 1: f-string SQL
Regex: f".*SELECT.*\{.*\}"
Example: f"SELECT * FROM users WHERE id={id}"

Pattern 2: String concatenation
Regex: ".*SELECT.*" \+ .*
Example: "SELECT * FROM users WHERE id=" + user_id

Pattern 3: format() method
Regex: \.format\(.*\)
Example: "SELECT * FROM users WHERE id={}".format(id)
```

---

## Testing Checklist

Before approving any fix:
- [ ] Parameterized query correctly passes data as separate parameters
- [ ] Injection payload test passes (0 results, not all results)
- [ ] Original functionality preserved (regression tests pass)
- [ ] Performance acceptable (<5% change)
- [ ] Code style matches repo (naming, formatting, docstrings)
- [ ] Related code updated (if same pattern elsewhere)

---

## Compliance & Audit

**Evidence to capture in PR**:
```
🤖 AI-Assisted Fix: Claude Sonnet 4.6
📋 Policy Applied: cwe_89_sqli.md v2.1
🎯 Tier Applied: Tier 1 (Parameterized Query)
📊 Confidence: 97%
✅ Tests: 158/158 passing
✅ SAST: CWE-89 finding cleared
```

**Governance Artifact**:
```json
{
  "finding_id": "checkmarx-2026-04-02-001",
  "remediation_id": "rem-2026-04-02-001",
  "policy_applied": "cwe_89_sqli.md",
  "policy_version": "2.1",
  "tier": 1,
  "model_used": "claude-sonnet-4.6",
  "confidence_score": 0.97,
  "timestamp": "2026-04-02T10:30:45Z"
}
```

---

## Success Criteria

A fix is considered successful if:
- ✅ Injection payload treated as literal (test passes)
- ✅ All existing tests still pass
- ✅ No performance regression
- ✅ Code approved by at least 1 developer
- ✅ Policy version recorded in audit log

---

## Historical Data

| Metric | Value |
|--------|-------|
| Tier 1 Success Rate | 98% |
| Avg Time to Fix | 5 min |
| Regressions | <1% |
| Developer Satisfaction | 4.8/5 ⭐ |

---

## References

- [NIST CWE-89](https://cwe.mitre.org/data/definitions/89.html)
- [OWASP SQL Injection](https://owasp.org/www-community/attacks/SQL_Injection)
- [Parameterized Queries Guide](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html)