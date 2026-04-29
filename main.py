from fastapi import FastAPI, UploadFile, File, HTTPException, Depends
from fastapi.responses import FileResponse
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel
from pathlib import Path
import shutil
import secrets
import hashlib
import sqlite3


app = FastAPI(
    title="FastAPI File Server Demo",
    description="A simple API-only file server with database-backed user registration, login, and user-specific file access.",
    version="3.0.0"
)

UPLOAD_DIR = Path("uploads")
DATA_DIR = Path("data")
DATABASE_FILE = DATA_DIR / "app.db"

UPLOAD_DIR.mkdir(exist_ok=True)
DATA_DIR.mkdir(exist_ok=True)

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")


class UserRegister(BaseModel):
    username: str
    password: str


def get_db_connection():
    conn = sqlite3.connect(DATABASE_FILE)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            username TEXT PRIMARY KEY,
            salt TEXT NOT NULL,
            password_hash TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
        """
    )

    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS tokens (
            token TEXT PRIMARY KEY,
            username TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (username) REFERENCES users(username)
        )
        """
    )

    conn.commit()
    conn.close()


def hash_password(password: str, salt: str):
    return hashlib.sha256((salt + password).encode("utf-8")).hexdigest()


def get_user_by_username(username: str):
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute(
        "SELECT username, salt, password_hash FROM users WHERE username = ?",
        (username,)
    )

    user = cursor.fetchone()
    conn.close()

    return user


def create_user(username: str, salt: str, password_hash: str):
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute(
        """
        INSERT INTO users (username, salt, password_hash)
        VALUES (?, ?, ?)
        """,
        (username, salt, password_hash)
    )

    conn.commit()
    conn.close()


def create_token(username: str):
    token = secrets.token_urlsafe(32)

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute(
        """
        INSERT INTO tokens (token, username)
        VALUES (?, ?)
        """,
        (token, username)
    )

    conn.commit()
    conn.close()

    return token


def get_username_by_token(token: str):
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute(
        """
        SELECT username FROM tokens
        WHERE token = ?
        """,
        (token,)
    )

    token_record = cursor.fetchone()
    conn.close()

    if not token_record:
        return None

    return token_record["username"]


def get_current_user(token: str = Depends(oauth2_scheme)):
    username = get_username_by_token(token)

    if not username:
        raise HTTPException(
            status_code=401,
            detail="Invalid or expired token"
        )

    return username


@app.on_event("startup")
def startup_event():
    init_db()


@app.get("/")
def read_root():
    return {
        "message": "Hello World",
        "status": "server is running"
    }


@app.post("/register")
def register(user: UserRegister):
    username = user.username.strip()
    password = user.password

    if not username:
        raise HTTPException(status_code=400, detail="Username cannot be empty")

    if len(password) < 6:
        raise HTTPException(status_code=400, detail="Password must be at least 6 characters")

    existing_user = get_user_by_username(username)

    if existing_user:
        raise HTTPException(status_code=400, detail="Username already exists")

    salt = secrets.token_hex(16)
    password_hash = hash_password(password, salt)

    create_user(username, salt, password_hash)

    user_upload_dir = UPLOAD_DIR / username
    user_upload_dir.mkdir(exist_ok=True)

    return {
        "message": "User registered successfully",
        "username": username
    }


@app.post("/login")
def login(form_data: OAuth2PasswordRequestForm = Depends()):
    username = form_data.username
    password = form_data.password

    user_record = get_user_by_username(username)

    if not user_record:
        raise HTTPException(status_code=401, detail="Invalid username or password")

    input_password_hash = hash_password(password, user_record["salt"])

    if input_password_hash != user_record["password_hash"]:
        raise HTTPException(status_code=401, detail="Invalid username or password")

    token = create_token(username)

    return {
        "access_token": token,
        "token_type": "bearer"
    }


@app.get("/me")
def get_me(current_user: str = Depends(get_current_user)):
    return {
        "username": current_user,
        "message": "You are currently logged in."
    }


@app.post("/logout")
def logout(token: str = Depends(oauth2_scheme)):
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute(
        "DELETE FROM tokens WHERE token = ?",
        (token,)
    )

    conn.commit()
    conn.close()

    return {
        "message": "Logged out successfully"
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