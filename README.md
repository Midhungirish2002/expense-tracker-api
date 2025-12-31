# Expense Tracker API

A Django REST Framework project to manage daily expenses efficiently.

# Expense Tracker API

A secure and scalable **Django REST Framework API** for managing daily expenses with **JWT authentication**, **admin-controlled user bans**, and **permission-based access control**.

---

## 🚀 Features

### 🔐 Authentication & Security
- JWT-based authentication (Access & Refresh tokens)
- Admin-controlled **user ban / unban**
- Token refresh support
- Global protection against banned users

### 👥 Role & Permission System
- Admin users (`is_staff`)
- Normal users with granular permissions
- Permission-based access for:
  - Viewing expenses
  - Creating expenses
  - Editing expenses
  - Deleting expenses
  - Viewing reports (totals)

### 💰 Expense Management
- Create, update, delete expenses
- List expenses (admin can view all users)
- Filter expenses by:
  - Date
  - Category
- View total expenses:
  - Per day
  - Per month

### 🛠 Admin Panel
- Manage users (ban / unban)
- Assign or revoke permissions
- View all expenses
- View user permissions visually

---

## 🧱 Tech Stack

- **Backend**: Django, Django REST Framework
- **Authentication**: Custom JWT (PyJWT)
- **Database**: PostgreSQL
- **Environment Config**: python-decouple
- **API Testing**: Postman

---

## 📁 Project Structure
expense_tracker_api/
├── expense_tracker/
│ ├── settings.py
│ ├── urls.py
│ └── utils.py
│
├── tracker/
│ ├── models.py
│ ├── views.py
│ ├── urls.py
│ ├── serializers.py
│ ├── authentication.py
│ ├── permissions.py
│ ├── permissions_utils.py
│ ├── permission_codes.py
│ └── admin.py
│
├── manage.py
├── requirements.txt
└── README.md
