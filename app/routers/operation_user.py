from fastapi import APIRouter, Depends, HTTPException, UploadFile, File, status
from fastapi.security import OAuth2PasswordRequestForm, OAuth2PasswordBearer
from app.utils.security import get_password_hash, verify_password, create_access_token, verify_token
from pymongo import MongoClient
from bson.objectid import ObjectId
import os
import shutil

router = APIRouter()

client = MongoClient("mongodb://localhost:27017/")
db = client.secure_file_sharing
users_collection = db.users
files_collection = db.files

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/operation/login")

UPLOAD_DIR = os.path.join(os.getcwd(), "uploads")
os.makedirs(UPLOAD_DIR, exist_ok=True)

ALLOWED_EXTENSIONS = {".pptx", ".docx", ".xlsx"}

@router.post("/login")
async def login(form_data: OAuth2PasswordRequestForm = Depends()):
    user = users_collection.find_one({"email": form_data.username, "role": "operation"})
    if not user or not verify_password(form_data.password, user["hashed_password"]):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    access_token = create_access_token(data={"sub": user["email"], "role": user["role"], "id": str(user["_id"])})
    return {"access_token": access_token, "token_type": "bearer"}

@router.post("/upload-file")
async def upload_file(file: UploadFile = File(...), token: str = Depends(oauth2_scheme)):
    payload = verify_token(token)
    if payload.get("role") != "operation":
        raise HTTPException(status_code=403, detail="Only operation users can upload files")
    
    ext = os.path.splitext(file.filename)[1]
    if ext not in ALLOWED_EXTENSIONS:
        raise HTTPException(status_code=400, detail="File type not allowed")
    
    save_path = os.path.join(UPLOAD_DIR, file.filename)
    with open(save_path, "wb") as buffer:
        shutil.copyfileobj(file.file, buffer)
    
    file_doc = {
        "filename": file.filename,
        "filepath": save_path,
        "uploaded_by": payload.get("id")
    }
    files_collection.insert_one(file_doc)
    return {"message": "File uploaded successfully"}