# main.py

from fastapi import FastAPI, File, UploadFile, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm, OAuth2PasswordBearer
from fastapi.middleware.cors import CORSMiddleware
import fitz
import re
import sqlite3
from typing import Optional, List, Dict, Any
from pydantic import BaseModel
import os
from datetime import datetime

import security # type: ignore

# ------------------- App Initialization and Setup -------------------
app = FastAPI()
origins = ["*"]
app.add_middleware(CORSMiddleware, allow_origins=origins, allow_credentials=True, allow_methods=["*"], allow_headers=["*"])
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATABASE_FILE = os.path.join(BASE_DIR, "..", "doctors.db")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/users/login")


# --- Pydantic Models (Data Schemas) ---
class UserCreate(BaseModel): email: str; password: str
class UserOut(BaseModel): id: int; email: str
class Token(BaseModel): access_token: str; token_type: str
# NEW: Models for report history
class ResultOut(BaseModel):
    test_name: str
    value: str
    normal_range: str
    status: str
class ReportOut(BaseModel):
    id: int
    filename: str
    upload_date: str
    results: List[ResultOut]


# --- Dependency to get current user ---
async def get_current_user(token: str = Depends(oauth2_scheme)) -> dict:
    credentials_exception = HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Could not validate credentials", headers={"WWW-Authenticate": "Bearer"})
    try:
        payload = security.jwt.decode(token, security.SECRET_KEY, algorithms=[security.ALGORITHM])
        email: str = payload.get("sub")
        if email is None: raise credentials_exception
    except security.JWTError:
        raise credentials_exception
    user = get_user_by_email(email)
    if user is None: raise credentials_exception
    return user


# --- Database Helper Functions ---
def get_db_connection():
    conn = sqlite3.connect(DATABASE_FILE)
    conn.row_factory = sqlite3.Row
    return conn

def get_user_by_email(email: str) -> Optional[dict]:
    conn = get_db_connection()
    user = conn.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()
    conn.close()
    return dict(user) if user else None

def create_user_in_db(user: UserCreate) -> Optional[dict]:
    conn = get_db_connection()
    hashed_password = security.get_password_hash(user.password)
    try:
        cursor = conn.cursor()
        cursor.execute("INSERT INTO users (email, hashed_password) VALUES (?, ?)", (user.email, hashed_password))
        conn.commit()
        return {"id": cursor.lastrowid, "email": user.email}
    except sqlite3.IntegrityError:
        return None
    finally:
        conn.close()

def save_analysis_report(user_id: int, filename: str, structured_results: List[Dict[str, Any]]):
    conn = get_db_connection()
    cursor = conn.cursor()
    upload_date = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    cursor.execute("INSERT INTO reports (user_id, filename, upload_date) VALUES (?, ?, ?)", (user_id, filename, upload_date))
    report_id = cursor.lastrowid
    results_to_insert = [(report_id, r['test_name'], r['value'], r['normal_range'], r['status']) for r in structured_results]
    cursor.executemany("INSERT INTO results (report_id, test_name, value, normal_range, status) VALUES (?, ?, ?, ?, ?)", results_to_insert)
    conn.commit()
    conn.close()

# NEW: Helper function to get a user's report history
def get_user_reports_from_db(user_id: int) -> List[Dict[str, Any]]:
    conn = get_db_connection()
    # Fetch all reports for the user, ordered by most recent
    reports_query = "SELECT id, filename, upload_date FROM reports WHERE user_id = ? ORDER BY upload_date DESC"
    reports_rows = conn.execute(reports_query, (user_id,)).fetchall()
    
    user_reports = []
    for report_row in reports_rows:
        report_dict = dict(report_row)
        # For each report, fetch its associated results
        results_query = "SELECT test_name, value, normal_range, status FROM results WHERE report_id = ?"
        results_rows = conn.execute(results_query, (report_dict['id'],)).fetchall()
        report_dict['results'] = [dict(res) for res in results_rows]
        user_reports.append(report_dict)
        
    conn.close()
    return user_reports

# (Other helper functions remain the same)
def query_doctors_db(specialty: Optional[str] = None, city: Optional[str] = None) -> List[Dict[str, Any]]: return []
def get_result_status(value_str: str, range_str: str) -> str: return "N/A"
def get_dashboard_stats_from_db(): return {}
def get_all_users_from_db(): return []

# ------------------- API Endpoints -------------------

# --- User Authentication Endpoints ---
@app.post("/users/register", response_model=UserOut, tags=["Users"])
def register_user(user: UserCreate):
    db_user = get_user_by_email(user.email)
    if db_user: raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="هذا البريد الإلكتروني مسجل بالفعل.")
    created_user = create_user_in_db(user)
    if not created_user: raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="حدث خطأ أثناء إنشاء الحساب.")
    return created_user

@app.post("/users/login", response_model=Token, tags=["Users"])
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
    user = get_user_by_email(form_data.username)
    if not user or not security.verify_password(form_data.password, user["hashed_password"]):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="البريد الإلكتروني أو كلمة المرور غير صحيحة", headers={"WWW-Authenticate": "Bearer"})
    access_token = security.create_access_token(data={"sub": user["email"]})
    return {"access_token": access_token, "token_type": "bearer"}

@app.get("/users/me", response_model=UserOut, tags=["Users"])
async def read_users_me(current_user: dict = Depends(get_current_user)):
    return current_user

# NEW: Endpoint to get the current user's report history
@app.get("/users/me/reports", response_model=List[ReportOut], tags=["Users"])
async def read_user_reports(current_user: dict = Depends(get_current_user)):
    """
    Protected endpoint to fetch all analysis reports for the logged-in user.
    """
    return get_user_reports_from_db(current_user["id"])

# --- Dashboard Endpoints ---
# (Dashboard endpoints remain the same)

# --- General and Main Feature Endpoints ---
@app.get("/", tags=["General"])
def read_root(): return {"message": "الـ Backend قام وشغال! (CORS شغالة)"}

@app.get("/doctors/", tags=["Doctors"])
def search_doctors(specialty: Optional[str] = None, city: Optional[str] = None): return query_doctors_db(specialty, city)

@app.post("/analyze/", tags=["Analysis"])
async def analyze_pdf(
    pdf_file: UploadFile = File(...),
    current_user: dict = Depends(get_current_user)
):
    try:
        # PDF parsing logic...
        pdf_bytes = await pdf_file.read()
        pdf_document = fitz.open(stream=pdf_bytes, filetype="pdf")
        full_text = "".join(page.get_text("text", sort=True) for page in pdf_document)
        pdf_document.close()
        
        structured_results = []
        pattern = re.compile(r"^(.*?)\s+([\d\.]+)\s+([\d\.\s\-–<>to]+)$")
        lines = full_text.split('\n')
        for line in lines:
            match = pattern.search(line.strip())
            if match:
                test_name = match.group(1).strip()
                if re.search(r'[a-zA-Z]{2,}', test_name) and "page" not in test_name.lower():
                    value = match.group(2).strip()
                    normal_range = match.group(3).strip()
                    status = get_result_status(value, normal_range)
                    structured_results.append({"test_name": test_name, "value": value, "normal_range": normal_range, "status": status})
        
        if structured_results:
            save_analysis_report(user_id=current_user["id"], filename=pdf_file.filename, structured_results=structured_results)

        return {"filename": pdf_file.filename, "structured_results": structured_results}
    except Exception as e:
        return {"error": f"An error occurred: {str(e)}"}
    

