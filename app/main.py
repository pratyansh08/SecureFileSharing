from fastapi import FastAPI
from app.routers import operation_user, client_user

app = FastAPI()

app.include_router(operation_user.router, prefix="/operation", tags=["Operation User"])
app.include_router(client_user.router, prefix="/client", tags=["Client User"])

@app.get("/")
async def root():
    return {"message": "Welcome to Secure File Sharing API"}