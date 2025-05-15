# Secure File Sharing System

This is a secure file-sharing system implemented using Python FastAPI framework with MongoDB as the database. The system has two types of users:

- **Operation User**: Can login and upload files (only pptx, docx, xlsx formats).
- **Client User**: Can sign up, verify email, login, list files, and download files via secure encrypted URLs.

## Features

- Secure file upload by Ops User.
- Client User signup with email verification.
- Secure encrypted download URLs only accessible by Client Users.
- REST APIs for all actions.
- File type validation and role-based access control.

## Technologies Used

- Python 3.13+
- FastAPI
- MongoDB
- Uvicorn (ASGI server)
