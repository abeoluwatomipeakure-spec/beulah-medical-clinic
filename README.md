# Beulah Medical Clinic — Final Local Build

This build keeps the Beulah laptop-first homepage and the connected Administrator → Staff/Doctor → Patient workflow.

## Start
1. Install Node.js 18+.
2. Double-click `start.bat`.
3. Open `http://localhost:3000`.

No npm install is required for this build because it uses Node's built-in modules.

## Initial local accounts
These are bootstrap accounts stored in the local database so a fresh installation can be entered. They are **not displayed on the sign-in page**.

- Administrator: `admin@beulah.test` / `Admin123!`
- Staff: `staff@beulah.test` / `Staff123!`
- Doctor: `doctor@beulah.test` / `Doctor123!`

Change bootstrap passwords before any real deployment.

## Patient cards
Patients do not need Gmail accounts.

Staff registration requires:
- Patient name
- Card Type: Personal or Family
- Card Number
- Card Name (personal card name or family card name)
- Optional phone, date of birth, sex and emergency contact

### Personal Card
One patient owns the Personal Card Number.

### Family Card
Several separate patient records can share the same Family Card Number and Family Card Name. Each family member still has a separate internal patient record. This prototype does not assign passwords to patients.

The same number is allowed to exist once as a Personal Card and also as a Family Card because the **Card Type is part of the identity**.

Patient login therefore asks for:
- Card Number
- Card Type

**Patients do not use or receive passwords in this build.**

Staff/Doctor/Administrator login asks for:
- Clinic email
- Password

## Staff patient confirmation
Staff can use **Find by Card** to enter a Card Number + Card Type. The system returns the matching patient record(s), and the staff member must open the patient page before recording vitals or payments.

## Team limits
The limits are configured in `server.js`:
- Staff: 15
- Doctors: 5
- Administrators: 3

Only the Administrator can add Staff or Doctor accounts. There is no public account-creation page.

## Included clinical workflow
- Appointments and reasons
- Operation consent records
- Patient history
- Vitals with recorder name and Staff ID
- Prescriptions
- Payment records including Cash / Transfer / Other and status
- Emergency requests
- Patient password reset by authorized clinic roles
- Audit trail
- Separate role-based workspaces

## App direction
The project can later be packaged as a phone app or installed as a progressive web app while keeping the same backend/API architecture.

## Revenue note
Simply having people download an app does not automatically generate money. A legitimate clinic app can later earn revenue through clinic services, approved paid features or subscriptions, or other transparent business arrangements. Any payment system should be configured for the clinic and handled securely; medical records should never be used as advertising data.

## Production warning
This local JSON build is for development/testing. A real deployment should use a secure database, HTTPS, encrypted secrets, proper backups, access logging, account recovery controls and a professional security/privacy review before storing real medical records.


## Monetization
Advertising is prepared but disabled by default. See `ADS-SETUP.md` to connect an approved provider. Ads are limited to public pages and kept away from private medical dashboards.


Final rule: patients do not create, receive, or reset passwords. Staff registers the Personal/Family Card and patient record; patient access uses Card Number + Card Type. Staff, Doctor, and Administrator use email + password. Staff, Doctor, and Administrator retain email/password authentication.
