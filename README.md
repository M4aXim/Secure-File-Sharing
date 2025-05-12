# 📁 FileShare: Accessible & Accountable File Storage for Everyone

The **goal** of this project is to build a file-sharing and storage platform that serves not just tech-savvy users, but **older people**, **non-technical users**, **organizations**, and **groups of people** who may struggle with overly complex or abstract systems.  
Our guiding principle is simple:

> Make storing and accessing files as easy as possible for *everyone* — even those who have never used Dropbox or Google Drive — while also empowering *staff* to keep things safe, clean, and organized.

This is **not** just another cloud app. This is a purpose-driven platform built with clarity, security, and **human simplicity** in mind.

---

## 🧠 The Philosophy Behind It

Most modern file-sharing systems assume too much of the user: that they know what "cloud" means, how to manage file permissions, how to troubleshoot login issues, or how to install apps.  
But we live in a world where many users — particularly **seniors**, **community centers**, **grassroots groups**, or **people with limited tech literacy** — don't want bells and whistles. They just want:

- "Where are my files?"  
- "How do I upload a photo?"  
- "How can I share this with my friend?"  

That's what **FileShare** solves.

At the same time, we recognize that in any shared space, there must be **rules**, and someone must be able to **enforce them**.  
That's where the **staff role** comes in. Staff members can monitor folder sharing, delete content that violates policies, and assist users by resetting passwords, verifying issues, and handling abuse reports — all within the same platform.

---

## 🧰 Feature Overview

### 🔐 Authentication
- **JWT-based login system** with email and password.  
- **Role management**: user, staff, and owner (admin-level).  
- **MongoDB integration** to persist user records.  
- **Password recovery** via email and secure reset mechanism.  
- **One-time-password (OTP) login** flow.

### 🗂️ Folder Management
- Users can **create folders**.  
- Files can be **uploaded, viewed, downloaded, and deleted**.  
- **Export folder as ZIP** (`/api/export-as-zip/:folderId`).  
- **Public/private toggle** for folders.  
- **Audit log** of every action.

### 👥 Sharing & Collaboration
- Invite friends by email to collaborate on a folder.  
- Friends get view/download/upload/delete/addUsers permissions as configured.  
- **Group sharing**: create groups, invite members, assign folder permissions.  
- **Staff moderation**: staff can view and remove invitations, friends, groups.

### 🖼️ Thumbnail Generation
- **Image thumbnails** (`/api/thumbnail/:folderId/:filename`) via Sharp.  
- **Video thumbnails** via FFmpeg + Sharp.

### 🔗 Temporary Download Links
- **Token-based download** for public/non-public folders (`/api/download-file?token=...`).  
- **Owner-generated presigned S3 links** valid for 1–24 hours (`/api/make-a-temporary-download-link`).

### 🤖 AI & Utility Endpoints
- **AI-driven recommendations**: `/api/recommended-files`.  
- **AI-powered content safety review** (periodic, email to owner).  
- **Random cat image** endpoint: `/api/curl/cats`.
- **Health check**: `/api/health`.

### 📊 Staff & Analytics
- **System stats** (users, folders, files, storage, averages, top users):  
  `/api/staff/stats/total-users`  
  `/api/staff/stats/total-folders`  
  `/api/staff/stats/total-public-folders`  
  `/api/staff/stats/total-private-folders`  
  `/api/staff/stats/total-files`  
  `/api/staff/stats/total-storage-used`  
  `/api/staff/stats/average-files-per-folder`  
  `/api/staff/stats/top-users-by-folders`  
  `/api/staff/stats/top-users-by-files`  
  `/api/staff/stats/recent-uploads`
- **Group stats & activity**:  
  `/api/staff/groups`  
  `/api/staff/groups/:groupId/activity`  
  `/api/staff/groups/stats`

---

## 🧰 Technical Stack

- **Backend:** Node.js + Fastify  
- **Database:** MongoDB  
- **File storage:** AWS S3  
- **Email:** Nodemailer (SMTP)  
- **Thumbnail & ZIP:** Sharp, FFmpeg, Archiver  
- **AI integration:** `https://ai.hackclub.com`  
- **Environment:** `.env` for secrets/config

---

## 🔧 Installation Guide

### 1. Clone the Repository
```bash
git clone https://github.com/M4aXim/Secure-File-Sharing.git
cd Secure-File-Sharing
```

### 2. Install Dependencies
```bash
npm install
```

### 3. Create a .env File
```dotenv
PORT=3000
OWNER_USERNAME=your_admin_username

# MongoDB
MONGO_URI=mongodb+srv://user:pass@cluster.mongodb.net/hackclub

# JWT & Password
JWT_SECRET=your_jwt_secret
SALT_ROUNDS=12
TOKEN_EXPIRATION=2h

# Email SMTP
EMAIL_HOST=smtp.example.com
EMAIL_PORT=587
EMAIL_USER=your@email.com
EMAIL_PASS=your_email_password
BCC=support@yourdomain.com

# AWS S3
AWS_ACCESS_KEY_ID=YOUR_AWS_KEY
AWS_SECRET_ACCESS_KEY=YOUR_AWS_SECRET
AWS_REGION=your-region
S3_BUCKET_NAME=your-bucket-name

#Cat API Key(for 404 page) - Get key at https://thecatapi.com/
CAT_API_KEY=your-key

# Rate limiting (optional)
RATE_LIMIT_MAX=100
RATE_LIMIT_WINDOW=1 minute

# MFA issuer (optional)
MFA_ISSUER=FileShare
```

### 4. Run the Server
```bash
npm start
```
Visit http://localhost:3000 in your browser.

---

## 🖥️ Frontend Pages

### Main User Pages
| File | Description |
|------|-------------|
| index.html | Login / Register |
| dashboard.html | User dashboard (my folders, shared, stats) |
| folder.html | View/upload/delete/download files |
| groups.html | Create and manage user groups, assign permissions, and handle group memberships |
| media_view-redirector.html | Redirect to media viewers |
| mp3.html | Audio player |
| mp4.html | Video player |
| contact.html | Contact/support form |
| privacy.html | Privacy policy |
| TOS.html | Terms of Service |
| law.html | Misuse & law enforcement compliance notice |


### Staff Pages
| File | Description |
|------|-------------|
| staff_login.html | Staff authentication |
| audit-log.html | View audit logs |
| delete-folder.html | Delete flagged folders |
| delete-invitation.html | Manage folder invitations |
| flag-folder.html | Flag inappropriate content |
| list-invitations.html | Browse pending invitations |
| list-of-folders.html | Browse all system folders |
| lookup-user.html | Search & view user details |
| reset-password.html | Staff password reset interface |
| scan-folder-contents.html | Inspect folder contents metadata |
| group-management.html | View & manage groups & permissions |

### Owner pages
| File | Description |
|------|-------------|
| delete-account.html | Account deletion interface |
| export.html | Export account data & logs |


---

## 📘 REST API Overview

All `/api/*` routes require JSON and use JWT (except public-folder access).

### Public & Authentication
```
POST   /api/register
POST   /api/login
POST   /api/request-otp
POST   /api/login-with-otp
GET    /api/verify-token
GET    /api/health
```

### User Folder & File Operations
```
GET    /api/my-folders
POST   /api/create-folder
GET    /api/folder-contents?folderID=...
POST   /api/upload-file/:folderId
GET    /api/download-file?token=...
GET    /api/unable-to-load/download-file?folderId=...&filename=...
GET    /api/export-as-zip/:folderId
GET    /api/open-file?folderId=...&filename=...
GET    /api/view-file/:folderId/*

POST   /api/add-friend
GET    /api/show-friends/:folderId
POST   /api/change-your-password
POST   /api/make-my-folder-public/:folderId
POST   /api/make-my-folder-private/:folderId
```

### Sharing & Groups
```
GET    /api/shared-folders
POST   /api/groups/create
GET    /api/groups/accept/:invitationId
GET    /api/groups/reject/:invitationId
GET    /api/groups/members/:groupId
GET    /api/groups/view-current-permissions/:groupID/:folderID
PUT    /api/folders/:folderId/groups/:groupId/permissions
GET    /api/show-group-I-created
GET    /api/show-groups-permissions
```

### Temporary Links & Tokens
```
GET    /api/generate-download-token?folderId=...&filename=...
POST   /api/make-a-temporary-download-link
```

### MFA Endpoints
```
POST   /api/setup-mfa
POST   /api/verify-mfa
DELETE /api/owner/mfa/disable
```

### Utility & AI
```
GET    /api/recommended-files
GET    /api/curl/cats
```

### Staff-Only Endpoints
```
middleware: [authenticate, verifyStaff]

GET    /api/staff/invitations
DELETE /api/staff/invitations/:invitationId
DELETE /api/staff/folders/:folderId/friends/:friendUsername
GET    /api/staff/audit-log?limit=...
GET    /api/staff/folder-contents?folderId=...
DELETE /api/staff/folders/:folderId
GET    /api/staff/users/:username
POST   /api/staff/reset-password/:username
DELETE /api/owner/delete-account
POST   /api/law-enforcement-request/:username

GET    /api/staff/stats/total-users
GET    /api/staff/stats/total-folders
GET    /api/staff/stats/total-public-folders
GET    /api/staff/stats/total-private-folders
GET    /api/staff/stats/total-files
GET    /api/staff/stats/total-storage-used
GET    /api/staff/stats/average-files-per-folder
GET    /api/staff/stats/top-users-by-folders
GET    /api/staff/stats/top-users-by-files
GET    /api/staff/stats/recent-uploads

GET    /api/staff/groups
GET    /api/staff/groups/:groupId/activity
GET    /api/staff/groups/stats
POST   /api/staff/groups/:groupId/flag
DELETE /api/staff/groups/:groupId/members/:username
```

---

## 👨‍👩‍👧‍👦 Ideal Use Cases

- Community centers sharing local event files and photos
- Religious groups organizing sermons, prayers, or bulletins
- Small non-profits keeping donor records or program files
- Senior users wanting a safe and simple place to share memories
- Schools/Clubs that need a private file zone without relying on Google

---

## 👮 Built-In Safety & Compliance

- JWT for secure session handling
- Staff-controlled moderation & audit trails
- Password strength checks & rate-limiting
- Email validation & one-time login codes
- AI-powered safety review of uploads
- Detailed audit.log for forensic review

---

## 🙏 Credits

Special thanks to [Hack Club](https://hackclub.com) for providing free AI resources that power this project. Learn more about their incredible mission to empower high school developers/hackers at [hackclub.com](https://hackclub.com).

For details about the AI integration, visit [ai.hackclub.com](https://ai.hackclub.com).

---

## 📝 License

This project is open source and free to use under the MIT License.