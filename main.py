from fastapi import FastAPI, UploadFile, File, HTTPException, Depends
from fastapi.responses import FileResponse
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel
from pathlib import Path
import shutil
import secrets
import json
import hashlib


app = FastAPI(
    title="FastAPI File Server Demo",
    description="A simple API-only file server with user registration, login, and user-specific file access.",
    version="2.0.0"
)

UPLOAD_DIR = Path("uploads")
DATA_DIR = Path("data")
USERS_FILE = DATA_DIR / "users.json"

UPLOAD_DIR.mkdir(exist_ok=True)
DATA_DIR.mkdir(exist_ok=True)

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")

# 登录 token 暂时存在内存里，服务器重启后会失效
active_tokens = {}


class UserRegister(BaseModel):
    username: str
    password: str


def load_users():
    if not USERS_FILE.exists():
        return {}

    with USERS_FILE.open("r", encoding="utf-8") as f:
        return json.load(f)


def save_users(users):
    with USERS_FILE.open("w", encoding="utf-8") as f:
        json.dump(users, f, indent=2)


def hash_password(password: str, salt: str):
    return hashlib.sha256((salt + password).encode("utf-8")).hexdigest()


def get_current_user(token: str = Depends(oauth2_scheme)):
    username = active_tokens.get(token)

    if not username:
        raise HTTPException(
            status_code=401,
            detail="Invalid or expired token"
        )

    return username


@app.get("/")
def read_root():
    return {
        "message": "Hello World",
        "status": "server is running"
    }


@app.post("/register")
def register(user: UserRegister):
    users = load_users()

    username = user.username.strip()
    password = user.password

    if not username:
        raise HTTPException(status_code=400, detail="Username cannot be empty")

    if len(password) < 6:
        raise HTTPException(status_code=400, detail="Password must be at least 6 characters")

    if username in users:
        raise HTTPException(status_code=400, detail="Username already exists")

    salt = secrets.token_hex(16)
    password_hash = hash_password(password, salt)

    users[username] = {
        "salt": salt,
        "password_hash": password_hash
    }

    save_users(users)

    user_upload_dir = UPLOAD_DIR / username
    user_upload_dir.mkdir(exist_ok=True)

    return {
        "message": "User registered successfully",
        "username": username
    }


@app.post("/login")
def login(form_data: OAuth2PasswordRequestForm = Depends()):
    users = load_users()

    username = form_data.username
    password = form_data.password

    if username not in users:
        raise HTTPException(status_code=401, detail="Invalid username or password")

    user_record = users[username]
    input_password_hash = hash_password(password, user_record["salt"])

    if input_password_hash != user_record["password_hash"]:
        raise HTTPException(status_code=401, detail="Invalid username or password")

    token = secrets.token_urlsafe(32)
    active_tokens[token] = username

    return {
        "access_token": token,
        "token_type": "bearer"
    }


@app.post("/upload")
async def upload_file(
    file: UploadFile = File(...),
    current_user: str = Depends(get_current_user)
):
    safe_filename = Path(file.filename).name

    if not safe_filename:
        raise HTTPException(status_code=400, detail="Invalid filename")

    user_upload_dir = UPLOAD_DIR / current_user
    user_upload_dir.mkdir(exist_ok=True)

    file_path = user_upload_dir / safe_filename

    with file_path.open("wb") as buffer:
        shutil.copyfileobj(file.file, buffer)

    return {
        "message": "Upload successful",
        "username": current_user,
        "filename": safe_filename
    }


@app.get("/files")
def list_files(current_user: str = Depends(get_current_user)):
    user_upload_dir = UPLOAD_DIR / current_user
    user_upload_dir.mkdir(exist_ok=True)

    files = [
        file.name
        for file in user_upload_dir.iterdir()
        if file.is_file()
    ]

    return {
        "username": current_user,
        "files": files,
        "count": len(files)
    }


@app.get("/download/{filename}")
def download_file(
    filename: str,
    current_user: str = Depends(get_current_user)
):
    safe_filename = Path(filename).name

    user_upload_dir = UPLOAD_DIR / current_user
    file_path = user_upload_dir / safe_filename

    if not file_path.exists() or not file_path.is_file():
        raise HTTPException(status_code=404, detail="File not found")

    return FileResponse(
        path=file_path,
        filename=safe_filename,
        media_type="application/octet-stream"
    )