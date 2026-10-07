# ConsentVault V14

ConsentVault is a patient-controlled health-data consent prototype.

## Core lifecycle
1. Patient signs in.
2. Patient enters the registered doctor/requester phone number.
3. Backend verifies the requester and automatically creates an Encounter ID.
4. The encounter appears automatically in the requester's account.
5. Requester creates a scoped request: data, conditions, purpose, duration.
6. Patient approves or denies.
7. Only after approval can the requester pay exactly ₹1 through Razorpay.
8. Verified payment changes the consent to ACTIVE.
9. Authorized reads are allowed only while ACTIVE.
10. Patient can revoke; expiry also blocks access.

## Wearable mode
Wearable Health is optional. The normal patient vault is shown when no wearable is connected. The patient explicitly connects the wearable space to unlock wearable metrics. The included live stream is clearly labelled simulated/demo-ready; a real Apple Health / Health Connect / vendor connector must be added for production device data.

## Demo requester
- Name: Dr. Maya Chen
- Requester ID: REQ-MAYA-01
- Phone: +919876543210
- Email: maya@consentvault.demo
- Password: requester123

Create your own patient account from the UI; patient details are not autofilled.

## Run
```bash
npm install
npm run dev
```
Open http://localhost:5173

## Razorpay
Create `.env` from `.env.example` and keep the secret server-side. Do not paste secrets into chat or frontend code.
