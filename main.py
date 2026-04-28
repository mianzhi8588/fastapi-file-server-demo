from fastapi import FastAPI, UploadFile, File, HTTPException
from fastapi.responses import FileResponse
from pathlib import Path
import shutil

app = FastAPI(title="FastAPI File Server Demo")

UPLOAD_DIR = Path("uploads")
UPLOAD_DIR.mkdir(exist_ok=True)


@app.get("/")
def read_root():
    return {
        "message": "Hello World",
        "status": "server is running"
    }


@app.post("/upload")
async def upload_file(file: UploadFile = File(...)):
    safe_filename = Path(file.filename).name

    if not safe_filename:
        raise HTTPException(status_code=400, detail="Invalid filename")

    file_path = UPLOAD_DIR / safe_filename

    with file_path.open("wb") as buffer:
        shutil.copyfileobj(file.file, buffer)

    return {
        "message": "Upload successful",
        "filename": safe_filename
    }


@app.get("/files")
def list_files():
    files = [
        file.name
        for file in UPLOAD_DIR.iterdir()
        if file.is_file()
    ]

    return {
        "files": files,
        "count": len(files)
    }


@app.get("/download/{filename}")
def download_file(filename: str):
    safe_filename = Path(filename).name
    file_path = UPLOAD_DIR / safe_filename

    if not file_path.exists() or not file_path.is_file():
        raise HTTPException(status_code=404, detail="File not found")

    return FileResponse(
        path=file_path,
        filename=safe_filename,
        media_type="application/octet-stream"
    )