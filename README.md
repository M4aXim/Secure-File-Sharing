# 📁 FileShare: Accessible & Accountable File Storage for Everyone

The **goal** of this project is to build a file‑sharing and storage platform that serves not just tech‑savvy users, but **older people**, **non‑technical users**, **organizations**, and **groups of people** who may struggle with overly complex or abstract systems.  
Our guiding principle is simple:

> Make storing and accessing files as easy as possible for *everyone* — even those who have never used Dropbox or Google Drive — while also empowering *staff* to keep things safe, clean, and organized.

This is **not** just another cloud app. This is a purpose‑driven platform built with clarity, security, and **human simplicity** in mind.

---

## 🧠 The Philosophy Behind It

Most modern file‑sharing systems assume too much of the user: that they know what "cloud" means, how to manage file permissions, how to troubleshoot login issues, or how to install apps.  
But we live in a world where many users — particularly **seniors**, **community centers**, **grassroots groups**, or **people with limited tech literacy** — don't want bells and whistles. They just want:

* "Where are my files?"  
* "How do I upload a photo?"  
* "How can I share this with my friend?"  

That's what **FileShare** solves.

At the same time, we recognize that in any shared space, there must be **rules**, and someone must be able to **enforce them**.  
That's where the **staff role** comes in. Staff members can monitor folder sharing, delete content that violates policies, and assist users by resetting passwords, verifying issues, and handling abuse reports — all within the same platform.

---

## 🧰 Feature Overview

### 🔐 Authentication
* **JWT‑based login system** with email and password.  
* **Role management**: user, staff, and owner (admin‑level).  
* **MongoDB integration** to persist user records.  
* **Password recovery** via email and secure reset mechanism.  

### 🗂️ Folder Management
* Users can **create folders**.  
* Files can be **uploaded, viewed, and deleted**.  
* Folders can be **shared with friends** via invitation email.  
* View contents in a clean UI with file sizes and timestamps.  

### 👥 Sharing & Collaboration
* Invite friends by email to collaborate on a folder.  
* Friends get view and download access, but not delete control.  
* Invitations are sent via email with accept/deny links.  
* Staff can monitor and manage invitations globally.  

### 🧑‍💼 Staff Tools
Staff users can:  

* View all pending invitations across the system.  
* Remove users from shared folders.  
* View metadata of folder contents.  
* Flag or delete folders that violate policy.  
* Look up user accounts and reset passwords.  
* Read recent entries in the audit log (no attachments).  

This helps **organizations keep their shared spaces clean, abuse‑free, and legally compliant**.

### 📝 Audit Logging
Every action a user takes is logged:

* Register  
* Login  
* Upload file  
* Create folder  
* Share folder  
* Staff actions  

All logs are saved to `audit.log` in JSON format, readable by staff via API. This is crucial for traceability and security.

---

## 🧑‍🔧 Technical Stack
* **Backend:** Node.js + Fastify  
* **Database:** MongoDB (hosted or local)  
* **Frontend:** Static HTML, CSS (Bulma), JavaScript  
* **File storage:** Local filesystem (can be switched to cloud later)  
* **Email:** Nodemailer via SMTP (supports Gmail, Proton, etc.)  

---

## 🔧 Installation Guide

### 1. Clone the Repository
```bash
git clone https://github.com/M4aXim/Secure-File-Sharing.git
cd Secure-File-Sharing
```

### 2. Install Node.js Dependencies
```bash
npm install
```

### 3. Create a .env File
```env
PORT=3000
OWNER_USERNAME=your_admin_username

# MongoDB
MONGO_URI=mongodb+srv://user:pass@yourcluster.mongodb.net

# JWT & Password
JWT_SECRET=your_super_secret_key
SALT_ROUNDS=12

# Email SMTP
EMAIL_HOST=smtp.example.com
EMAIL_PORT=587
EMAIL_USER=your@email.com
EMAIL_PASS=yourpassword
BCC=support@yourdomain.com

# Optional
RATE_LIMIT_MAX=100
RATE_LIMIT_WINDOW=1 minute
```

### 4. Run the Server
```bash
npm start
```
Then visit http://localhost:3000 in your browser.

---

## 🖥️ Pages Included

### Main User Pages
| Page | Description |
|------|-------------|
| index.html | Login / Register |
| dashboard.html | Main user dashboard (folders, shared, change password) |
| folder.html | View folder contents, upload files, delete/view/download |
| contact.html | Contact form for user support |
| privacy.html | Privacy policy page |
| TOS.html | Terms of Service page |
| law.html | A formal notice outlining FileShare’s policy on misuse, affirming cooperation with law enforcement and providing contact details for reporting abuse.|
| media_view-redirector.html | Dynamic redirect to media viewers |
| mp3.html | Audio file viewer |
| mp4.html | Video file viewer |

### Staff Pages
| Page | Description |
|------|-------------|
| staff_login.html | Staff authentication portal |
| audit-log.html | Staff view for audit logs |
| delete-folder.html | Interface for folder deletion |
| delete-invitation.html | Interface for managing invitations |
| flag-folder.html | Interface for flagging inappropriate content |
| Hello.html | Staff welcome page |
| list-invitations.html | View and manage all pending invitations |
| list-of-folders.html | Browse all folders in the system |
| lookup-user.html | Search for and view user information |
| reset-password.html | Interface for staff to reset user passwords |
| scan-folder-contents.html | Detailed folder content inspection tool |

---

## 📘 REST API Overview
Every route under /api/ is documented and uses JWT tokens.

```bash
POST /api/register
POST /api/login
GET  /api/verify-token
GET  /api/my-folders
POST /api/create-folder
GET  /api/folder-contents?folderID=...
POST /api/upload-file/:folderId
GET  /api/download-file?token=...
POST /api/add-friend
POST /api/change-your-password
```

### Staff‑Only Endpoints
```swift
GET    /api/staff/invitations
DELETE /api/staff/invitations/:id
DELETE /api/staff/folders/:id/friends/:username
GET    /api/staff/audit-log
GET    /api/staff/folder-contents
DELETE /api/staff/folders/:folderId
GET    /api/staff/users/:username
POST   /api/staff/reset-password/:username
```

---

## 🛠️ Customization Tips
* Swap the filesystem backend with S3 or Google Cloud Storage.
* Theme the UI with custom CSS for organizational branding.
* Add 2FA or CAPTCHA for extra login security.
* Extend staff privileges with more granular permission levels.

---

## 👨‍👩‍👧‍👦 Ideal Use Cases
* Community centers sharing local event files and photos
* Religious groups organizing sermons, prayers, or bulletins
* Small non‑profits keeping donor records or program files
* Senior users wanting a safe and simple place to share memories
* Schools/Clubs that need a private file zone without relying on Google

---

## 👮 Built‑In Safety Mechanisms
* JWT for secure session handling
* Staff‑controlled content moderation
* Password strength checks
* Email validation and recovery
* Rate limiting for brute‑force prevention
* Audit trail for accountability

---

## 📝 License
This project is open source and free to use under the MIT License.
