# Raf Demo Bank

Raf Demo Bank is a small intentionally vulnerable web application designed for demonstrating web application security issues in a realistic but controlled environment.  
The main focus of this project is a **NoSQL injection vulnerability** in a JSON-based transfer API, combined with **HMAC-signed requests** and a helper Burp Suite extension.

> ⚠️ **Warning**  
> This project is for educational and lab use only. Do **not** deploy it on the public internet or in any production environment.

---

## 1. Project Overview

The project consists of two main parts:

1. **Raf Demo Bank Web Application**
   - Backend: **Node.js + Express**
   - Database: **MongoDB (Mongoose)**
   - View engine: **EJS**
   - Purpose: simulate a small online banking portal with user accounts, balances, and an API for money transfers

2. **Burp Suite Extension: Request-Signer-Extension**
   - Implemented in **Jython**
   - Adds a custom Burp tab: **"Request-Signer-Extension"**
   - Automatically re-signs JSON requests with an HMAC before they are sent
   - Can be used to reproduce both legitimate and malicious (NoSQL injection) requests in Repeater / Intruder / Scanner etc.

---

## 2. Features

### Web application

- User authentication with username + password.
- Personal profile page:
  - Full name (First name, Last name, Middle name)
  - IBAN
  - Account balance (UAH)
  - Per-user **HMAC Secret** used to sign transfer requests.
- Admin dashboard:
  - View all users
  - View their IBANs, balances, and HMAC secrets
  - Passwords are not shown in the dashboard view
- Intentionally vulnerable **transfer API** (`/api/transfer`) with:
  - HMAC verification based on a JSON payload
  - Limited response data (for blind-style exploitation)

### Burp extension

- Tab name: **Request-Signer-Extension**
- Configurable parameters:
  - HMAC secret
  - Target URL filters (substring match)
  - Parameter order used for canonical JSON payload
  - Tool scope (Proxy, Repeater, Intruder, Scanner)
- Additional functionality:
  - Test panel to compute a signature for a sample JSON body
  - Debug log area to inspect payloads, signatures and which requests were signed

---

## 3. Architecture

- **Backend:** Node.js, Express
- **Database:** MongoDB, Mongoose
- **Views:** EJS templates (`views/`)
- **Static assets:** CSS in `public/styles.css`
- **Models:** `models/User.js`
- **Burp extension:** `burp-extension/Request-Signer-Extension.py`

On startup, the application connects to MongoDB and seeds a set of test users if the database is empty.

---

## 4. Installation and Setup

### 5.1. Clone the repository & Install Node.js dependencies

```bash
git clone https://github.com/g-fraid/raf-demo-bank.git
cd raf-demo-bank
npm install
```

### 5.2. Run MongoDB & Start the application

```bash
sudo systemctl start mongodb
npm start
```

The server will listen on: `http://0.0.0.0:3000`

---

## 6. Test Users

- `admin:RafAdminLatte!` (admin)
- `ipetrenko:GreenForest!` (User)

Other user can be found and edited in `server.js`.

---

## 7. Transfer API and HMAC Signing

### 7.1. Endpoint

```http
POST /api/transfer
Content-Type: application/json
```

### 7.2. JSON request body

```json
{
  "senderIban": "UA...",
  "receiverIban": "UA...",
  "amount": 100,
  "signature": "hex-encoded HMAC"
}
```
