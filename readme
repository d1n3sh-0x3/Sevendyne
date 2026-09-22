# Cross-Tenant IDOR — Employee Deletion & Ownership Takeover (Sevendyne HRMS)

| | |
|---|---|
| **Target** | Sevendyne HRMS |
| **Vulnerability Class** | IDOR / Broken Object-Level Authorization (CWE-639) |
| **Endpoint** | `GET /app/employee/delete-employee/<id>/` |
| **Tested On** | 2026-09-03 |
| **Severity** | High — CVSS 3.1: `8.1` (`AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:H/A:H`) |
| **Author** | Dinesh (Gollapalli Dinesh Kumar Goud) |

> **Disclosure note:** This write-up describes a finding identified during an authorized security assessment. Redact any client-identifying details below if you don't have explicit permission to publish them publicly.

---

## Summary

Sevendyne HRMS is a multi-tenant application in which each client account belongs to a "company" (tenant). The employee-delete endpoint retrieves the target `Employee` object by primary key only, with **no check that the employee belongs to the requester's own company**. As a result, any authenticated client — including a freshly self-registered, unprivileged account — can soft-delete another tenant's employee record. The same operation also **reassigns the deleted record's ownership to the attacker's company**, so the attacker both destroys the victim's data and takes ownership of it. The endpoint also accepts a plain `GET` request with no CSRF token.

## Test Accounts

| Role | Account | Company | Company ID |
|------|---------|---------|------------|
| Attacker (Tenant B) | `dastcompanyB` — standard, self-registered HRMS Client, no special role | DAST Tenant B | `52b9eee0-1a15-40b3-9c1a-bcf0d7e224ee` |
| Victim (Tenant A) | — | Sevendyne Demo Corp | `57da000d-98a7-40ab-b792-ef941f2d10c4` |
| Target employee | — | Belongs to Tenant A | `8c15a176-58af-489a-8a82-70ccef72121f` |

The attacker never authenticates as, or steals credentials from, the victim tenant — only their own valid session and the victim's object ID are needed.

## Steps to Reproduce

**1. Send a plain `GET` request — no CSRF token required:**

```http
GET /app/employee/delete-employee/8c15a176-58af-489a-8a82-70ccef72121f/ HTTP/1.1
Host: localhost:8000
Cookie: sessionid=<attacker session>
```

**Result:** `HTTP 200`

```json
{"status":"true","title":"Successfully Deleted","message":"Employee Successfully Deleted."}
```

<!-- 📷 Screenshot 1: request/response above showing the successful cross-tenant delete
     ![Cross-tenant delete request and 200 response](images/finding-delete-request.png) -->
<img width="955" height="480" alt="1" src="https://github.com/user-attachments/assets/5a980516-a048-4207-9c70-5cdc527efb40" />
<img width="952" height="476" alt="3" src="https://github.com/user-attachments/assets/1f1da701-a8c3-4468-9771-3a2f2585b4f2" />
<img width="937" height="422" alt="2" src="https://github.com/user-attachments/assets/b8428c98-c96d-425f-a4b5-e58d5ce5e80c" />

**2. Verification** — the target employee's `company` field flips from Tenant A (`57da000d-98a7-40ab-b792-ef941f2d10c4`) to the attacker's company, **DAST Tenant B** (`52b9eee0-1a15-40b3-9c1a-bcf0d7e224ee`), and the record is marked deleted.

<!-- 📷 Screenshot 2: database/admin view confirming the record's company field
     reassigned to the attacker's tenant and `is_deleted = true`
     ![Employee record reassigned and marked deleted](images/finding-record-reassigned.png) -->

| | Expected | Actual |
|---|----------|--------|
| Response | `403 Forbidden` / `404 Not Found`, no modification | `200 OK` — victim's employee deleted and reassigned |

## Impact

An attacker with only a standard, unprivileged client account can:
- Destroy another tenant's employee records (data availability breach)
- Simultaneously reassign those records to their own company (data integrity breach)
- Trigger the deletion via CSRF (cross-site link or `<img>` tag), since the endpoint accepts `GET` with no CSRF token, meaning it can even be fired against a logged-in victim without their knowledge

Because the same missing check applies to every `Employee` record, this affects **all tenants** on the platform, not a single victim.

## Root Cause

The endpoint fetches the object by primary key alone. The authorization layer verifies only that the requesting user *has a current company* — never that the **specific employee requested belongs to that company**.

## Remediation

1. Scope the lookup to the requester's company:
   ```python
   employee = get_object_or_404(Employee, pk=pk, company=current_company, is_deleted=False)
   ```
2. Never reassign an object's tenant/company as a side effect of delete.

3. Require `POST` for this and every other state-changing endpoint (`@require_POST`) and enforce CSRF protection.
4. Add a cross-tenant authorization test proving Tenant B cannot delete Tenant A's employee.

---

*Write-up prepared for portfolio/reference purposes. Testing was performed against a local instance (`localhost:8000`) with authorization.*
