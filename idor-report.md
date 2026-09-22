Subject: Security Finding – Cross-Tenant IDOR (Broken Object-Level Authorization) in Sevendyne HRMS

Target: Sevendyne HRMS (tested at http://localhost:8000)
Tested on: 2026-09-03
Bug class: IDOR / Broken Object-Level Authorization (multi-tenant isolation failure)
Overall severity: High

================================================================
TEST ACCOUNTS USED
================================================================
- Attacker (Tenant B): username "dastcompanyB", HRMS Client role, owns company
  "DAST Tenant B" (id 52b9eee0-1a15-40b3-9c1a-bcf0d7e224ee). A normal
  self-registered client account — no special role or permission.
- Victim (Tenant A): company "Sevendyne Demo Corp"
  (id 57da000d-98a7-40ab-b792-ef941f2d10c4), owned by a different client.

Both are standard tenants. The attacker only ever uses their own logged-in
session; the only thing changed in each request is the object ID in the URL.

================================================================
FINDING 1 – Cross-tenant company read AND write via /company/<id>/ and /company/edit/<id>/
================================================================

DESCRIPTION
The company view and edit endpoints look up the Company object by its ID alone
and do not check that the object belongs to the requesting tenant. Any
authenticated HRMS client can read and modify another company's record simply by
placing the victim's company ID in the URL. I confirmed both read and write
against a company owned by a different tenant.

SEVERITY
High — CVSS 3.1: 8.1 (AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)
An attacker with only a free client account can read and overwrite any other
tenant's company profile.

STEPS TO REPRODUCE
Attacker session: logged in as "dastcompanyB".
Victim company ID: 57da000d-98a7-40ab-b792-ef941f2d10c4

1) READ another tenant's company:
   GET /company/57da000d-98a7-40ab-b792-ef941f2d10c4/ HTTP/1.1
   Host: localhost:8000
   Cookie: sessionid=<attacker session>

   Result: HTTP 200. The response returns Tenant A's private company data:
     name        = "Sevendyne Demo Corp"
     contact     = "Demo Admin"
     address     = "123 Demo Street"
     email       = "demo@sevendyne.com"

2) WRITE (modify) another tenant's company:
   GET /company/edit/57da000d-98a7-40ab-b792-ef941f2d10c4/  -> returns the
   pre-filled edit form for Tenant A (HTTP 200), then submit:

   POST /company/edit/57da000d-98a7-40ab-b792-ef941f2d10c4/ HTTP/1.1
   Host: localhost:8000
   Cookie: sessionid=<attacker session>
   Content-Type: application/x-www-form-urlencoded

   csrfmiddlewaretoken=<token>&name=Sevendyne Demo Corp&contact_person=Demo Admin
   [DAST-IDOR-PROOF-VIA-COMPANY-B]&address=123 Demo Street&country=1&state=1
   &city=Demo City&postal_code=10001&email=demo@sevendyne.com&phone=+1234567890

   Result: HTTP 200
   {"status":"true","message":"Company updated successfully."}

3) Verification: Tenant A's company "contact_person" field is now
   "Demo Admin [DAST-IDOR-PROOF-VIA-COMPANY-B]", confirming the attacker (Tenant B)
   modified another tenant's record.

Expected: 403 Forbidden or 404 Not Found (object not owned by requester).
Actual:   200 OK, victim data returned and modified.

IMPACT
An attacker with a standard client account can read every other tenant's company
profile (contact person, address, email, phone) and overwrite it. Because the
same missing check applies to all companies, this affects every tenant on the
platform, not a single record.

REMEDIATION
Scope every object lookup to the requesting tenant, e.g.:
  get_object_or_404(Company, pk=pk, id=current_company.id, is_deleted=False)
Apply the same tenant-scoped queryset to BOTH the GET (view) and POST (edit)
paths, and add an authorization test that confirms a client cannot access another
company's ID.

================================================================
FINDING 2 – Cross-tenant employee deletion + ownership takeover via /app/employee/delete-employee/<id>/
================================================================

DESCRIPTION
The employee-delete endpoint retrieves the target employee by primary key only,
with no filter tying the employee to the requester's company. As a result, an
authenticated client can soft-delete an employee belonging to a different tenant.
The same operation also reassigns the deleted employee record to the attacker's
company, so the attacker both destroys the victim's data and takes ownership of
the record. The endpoint accepts a plain GET request with no CSRF token.

SEVERITY
High — CVSS 3.1: 8.1 (AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:H/A:H)
An attacker with a free client account can delete other tenants' employee records
and reassign ownership to themselves.

STEPS TO REPRODUCE
Attacker session: logged in as "dastcompanyB" (company id 52b9eee0-...).
Target employee: an employee belonging to Tenant A (company 57da000d-...),
id 8c15a176-58af-489a-8a82-70ccef72121f.

1) As the attacker, send a plain GET (no CSRF token):
   GET /app/employee/delete-employee/8c15a176-58af-489a-8a82-70ccef72121f/ HTTP/1.1
   Host: localhost:8000
   Cookie: sessionid=<attacker session>

   Result: HTTP 200
   {"status":"true","title":"Successfully Deleted",
    "message":"Employee Successfully Deleted."}

2) Verification: the target employee record's company field changed from
   Tenant A (57da000d-98a7-40ab-b792-ef941f2d10c4) to the attacker's company
   "DAST Tenant B" (52b9eee0-1a15-40b3-9c1a-bcf0d7e224ee), and the record is
   marked deleted. The employee originally belonged to Tenant A.

Expected: 403 Forbidden or 404 Not Found, and no modification.
Actual:   200 OK, victim's employee deleted and reassigned to the attacker.

IMPACT
An attacker with a standard client account can destroy another tenant's employee
records and simultaneously reassign those records to their own company. This is a
cross-tenant data-integrity and availability breach affecting all tenants. Because
the endpoint also accepts GET without a CSRF token, the deletion can additionally
be triggered against a logged-in user via a cross-site link or image.

REMEDIATION
1) Scope the lookup to the requester's company:
   employee = get_object_or_404(Employee, pk=pk, company=current_company,
                                is_deleted=False)
2) Never reassign the object's company on delete.
3) Require POST for this and all other state-changing endpoints (@require_POST)
   and enforce CSRF protection.
4) Add a cross-tenant authorization test proving one client cannot delete
   another company's employee.

================================================================
COMMON ROOT CAUSE
================================================================
Both issues stem from the same pattern: objects are fetched by ID (pk) without a
company/tenant filter, and the authorization decorators verify only that the user
has *a* current company — not that the *requested object* belongs to it. Enforcing
a tenant-scoped queryset on every object access resolves both findings.
