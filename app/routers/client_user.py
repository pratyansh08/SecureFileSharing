from fastapi import APIRouter, Depends, HTTPException, status, BackgroundTasks, Query
from pydantic import BaseModel, EmailStr
from app.utils.security import get_password_hash, verify_password, create_access_token, verify_token
from pymongo import MongoClient
from bson.objectid import ObjectId
from fastapi.security import OAuth2PasswordRequestForm, OAuth2PasswordBearer
from fastapi.responses import JSONResponse, FileResponse
import os
import secrets
from datetime import datetime, timedelta
from jose import jwt

router = APIRouter()

client = MongoClient("mongodb://localhost:27017/")
db = client.secure_file_sharing
users_collection = db.users
files_collection = db.files

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/client/login")

UPLOAD_DIR = os.path.join(os.getcwd(), "uploads")
os.makedirs(UPLOAD_DIR, exist_ok=True)

class UserSignup(BaseModel):
    email: EmailStr
    password: str

# Dummy email send function (prints to console)
def send_verification_email(email: str, verification_token: str):
    verification_url = f"http://localhost:8000/client/verify-email?token={verification_token}"
    print(f"Send verification email to {email} with URL: {verification_url}")

@router.post("/signup")
async def signup(user: UserSignup, background_tasks: BackgroundTasks):
    existing = users_collection.find_one({"email": user.email})
    if existing:
        raise HTTPException(status_code=400, detail="Email already registered")
    hashed_password = get_password_hash(user.password)
    verification_token = secrets.token_urlsafe(16)
    user_doc = {
        "email": user.email,
        "hashed_password": hashed_password,
        "is_verified": False,
        "role": "client",
        "verification_token": verification_token,
    }
    users_collection.insert_one(user_doc)
    background_tasks.add_task(send_verification_email, user.email, verification_token)
    encrypted_url = f"http://localhost:8000/client/verify-email?token={verification_token}"
    return {"message": "User registered successfully. Verification email sent.", "verification_url": encrypted_url}

@router.get("/verify-email")
async def verify_email(token: str = Query(...)):
    user = users_collection.find_one({"verification_token": token})
    if not user:
        raise HTTPException(status_code=400, detail="Invalid verification token")
    if user.get("is_verified"):
        return {"message": "Email already verified."}
    users_collection.update_one({"_id": user["_id"]}, {"$set": {"is_verified": True}, "$unset": {"verification_token": ""}})
    return {"message": "Email verified successfully."}

@router.post("/login")
async def login(form_data: OAuth2PasswordRequestForm = Depends()):
    user = users_collection.find_one({"email": form_data.username, "role": "client"})
    if not user or not verify_password(form_data.password, user["hashed_password"]):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    if not user.get("is_verified"):
        raise HTTPException(status_code=403, detail="Email not verified")
    access_token = create_access_token(data={"sub": user["email"], "role": user["role"], "id": str(user["_id"])})
    return {"access_token": access_token, "token_type": "bearer"}

@router.get("/list-files")
async def list_files(token: str = Depends(oauth2_scheme)):
    payload = verify_token(token)
    if payload.get("role") != "client":
        raise HTTPException(status_code=403, detail="Only client users allowed")
    files = []
    for file in files_collection.find():
        files.append({"file_id": str(file["_id"]), "filename": file["filename"]})
    return {"files": files}

@router.get("/download-file/{file_id}")
async def download_file(file_id: str, token: str = Depends(oauth2_scheme)):
    payload = verify_token(token)
    if payload.get("role") != "client":
        raise HTTPException(status_code=403, detail="Only client users allowed")
    file_doc = files_collection.find_one({"_id": ObjectId(file_id)})
    if not file_doc:
        raise HTTPException(status_code=404, detail="File not found")

    # Generate a secure encrypted URL for download with a short expiry token
    download_token = create_access_token(data={"file_id": file_id}, expires_delta=timedelta(minutes=15))
    download_url = f"http://localhost:8000/client/download-by-token?token={download_token}"
    return {"download-link": download_url, "message": "success"}

@router.get("/download-by-token")
async def download_by_token(token: str):
    try:
        payload = jwt.decode(token, "your_secret_key_here_change_it", algorithms=["HS256"])
        file_id = payload.get("file_id")
    except Exception:
        raise HTTPException(status_code=403, detail="Invalid or expired token")

    file_doc = files_collection.find_one({"_id": ObjectId(file_id)})
    if not file_doc:
        raise HTTPException(status_code=404, detail="File not found")

    file_path = file_doc.get("filepath")
    if not os.path.exists(file_path):
        raise HTTPException(status_code=404, detail="File not found on server")
    return FileResponse(file_path, media_type="application/octet-stream", filename=file_doc["filename"])