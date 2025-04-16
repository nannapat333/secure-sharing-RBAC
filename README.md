# 📁 Secure File Sharing System with RBAC and End-to-End Encryption

This is a secure web-based file sharing system that supports:
🔐 End-to-End Encryption (AES + RSA)
👥 Role-Based Access Control (RBAC) (Admin, Uploader, Viewer, Guest)
📂 Secure upload, download, and viewing of sensitive files
🕵️‍♂️ Access control with per-user encrypted keys
⏳ Optional time-limited access for guests
Built with Flask, SQLAlchemy, and modern HTML/CSS for a user-friendly experience.

## Features

Login / Registration
Role-based permissions:
    - Admin: Can view, download, and delete any file
    - Uploader: Upload + share files with specific users or roles
    - Viewer: Can only view/download shared files
    - Guest: Can only view (no download allowed)
AES-Encrypted File Storage
RSA Keypair per User
Per-user AES Key Sharing
Access Control UI
Encrypted PDFs, Images, and Text
Auto-share with Admin
Friendly error handling

## Tech Stacks

Python (Flask)
SQLite + SQLAlchemy
Flask-Login
AES / RSA Cryptography
Jinja2 Templates (HTML/CSS)
Bootstrap 5 for UI
