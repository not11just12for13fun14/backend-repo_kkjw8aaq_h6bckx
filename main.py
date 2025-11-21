import os
from datetime import datetime, timedelta, timezone, date
from typing import Optional, List, Dict, Any

from fastapi import FastAPI, HTTPException, Depends, status, Body
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import BaseModel, Field, EmailStr
from bson import ObjectId

from database import db

# =====================
# Auth / Security Setup
# =====================
SECRET_KEY = os.getenv("SECRET_KEY", "supersecretkey-change-me")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24 * 7  # 7 days

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/login")

# =====================
# FastAPI App
# =====================
app = FastAPI(title="WeightTrack API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# =====================
# Helpers
# =====================
class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"

class TokenData(BaseModel):
    user_id: Optional[str] = None


def get_password_hash(password: str) -> str:
    return pwd_context.hash(password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


def oid(id_str: str) -> ObjectId:
    try:
        return ObjectId(id_str)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid ID format")


def serialize_doc(doc: Dict[str, Any]) -> Dict[str, Any]:
    if not doc:
        return doc
    doc = dict(doc)
    if "_id" in doc:
        doc["id"] = str(doc.pop("_id"))
    # Convert datetimes to ISO
    for k, v in list(doc.items()):
        if isinstance(v, datetime):
            doc[k] = v.astimezone(timezone.utc).isoformat()
        if isinstance(v, date) and not isinstance(v, datetime):
            # keep date as ISO string
            doc[k] = v.isoformat()
    return doc


# =====================
# Schemas
# =====================
class UserCreate(BaseModel):
    email: EmailStr
    password: str = Field(min_length=8)

class UserPublic(BaseModel):
    id: str
    email: EmailStr
    created_at: str

class PersonCreate(BaseModel):
    name: str
    nickname: Optional[str] = None
    starting_weight_kg: Optional[float] = Field(None, ge=20, le=300)
    height_cm: Optional[float] = Field(None, ge=50, le=250)
    date_of_birth: Optional[date] = None

class PersonUpdate(PersonCreate):
    pass

class WeightEntryCreate(BaseModel):
    datetime: datetime
    weight_kg: float = Field(..., ge=20, le=300)
    note: Optional[str] = None

class WeightEntryUpdate(BaseModel):
    datetime: Optional[datetime] = None
    weight_kg: Optional[float] = Field(None, ge=20, le=300)
    note: Optional[str] = None

class GoalCreate(BaseModel):
    start_date: date
    end_date: date
    target_weight_kg: float = Field(..., ge=20, le=300)
    lock_start_to_first_log: Optional[bool] = False

class GoalUpdate(BaseModel):
    start_date: Optional[date] = None
    end_date: Optional[date] = None
    target_weight_kg: Optional[float] = Field(None, ge=20, le=300)
    lock_start_to_first_log: Optional[bool] = None
    start_weight_kg: Optional[float] = Field(None, ge=20, le=300)

class MilestoneCreate(BaseModel):
    title: str
    target_date: date
    target_weight_kg: float = Field(..., ge=20, le=300)
    note: Optional[str] = None

class MilestoneUpdate(BaseModel):
    title: Optional[str] = None
    target_date: Optional[date] = None
    target_weight_kg: Optional[float] = Field(None, ge=20, le=300)
    note: Optional[str] = None


# =====================
# Auth dependencies
# =====================
async def get_current_user(token: str = Depends(oauth2_scheme)) -> Dict[str, Any]:
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id: str = payload.get("sub")
        if user_id is None:
            raise credentials_exception
        token_data = TokenData(user_id=user_id)
    except JWTError:
        raise credentials_exception

    user = db["user"].find_one({"_id": oid(token_data.user_id)})
    if not user:
        raise credentials_exception
    return serialize_doc(user)


# =====================
# Routes: Health
# =====================
@app.get("/")
def root():
    return {"name": "WeightTrack API", "status": "ok"}

@app.get("/test")
def test_database():
    try:
        names = db.list_collection_names()
        return {"database": "connected", "collections": names}
    except Exception as e:
        return {"database": "error", "error": str(e)}


# =====================
# Routes: Auth
# =====================
@app.post("/auth/signup", response_model=UserPublic)
def signup(payload: UserCreate):
    existing = db["user"].find_one({"email": payload.email.lower()})
    if existing:
        raise HTTPException(status_code=400, detail="Email already registered")
    now = datetime.now(timezone.utc)
    user_doc = {
        "email": payload.email.lower(),
        "password_hash": get_password_hash(payload.password),
        "created_at": now,
    }
    res = db["user"].insert_one(user_doc)
    user_doc["_id"] = res.inserted_id
    s = serialize_doc(user_doc)
    return {"id": s["id"], "email": s["email"], "created_at": s["created_at"]}

@app.post("/auth/login", response_model=Token)
def login(form_data: OAuth2PasswordRequestForm = Depends()):
    user = db["user"].find_one({"email": form_data.username.lower()})
    if not user or not verify_password(form_data.password, user.get("password_hash", "")):
        raise HTTPException(status_code=400, detail="Incorrect email or password")
    access_token = create_access_token({"sub": str(user["_id"])})
    return {"access_token": access_token, "token_type": "bearer"}

@app.get("/me", response_model=UserPublic)
def me(current_user: Dict[str, Any] = Depends(get_current_user)):
    return {
        "id": current_user["id"],
        "email": current_user["email"],
        "created_at": current_user.get("created_at", ""),
    }

# =====================
# Routes: Persons
# =====================
@app.get("/persons")
def list_persons(current_user: Dict[str, Any] = Depends(get_current_user)):
    docs = db["person"].find({"user_id": current_user["id"]}).sort("created_at", 1)
    return [serialize_doc(d) for d in docs]

@app.post("/persons")
def create_person(payload: PersonCreate, current_user: Dict[str, Any] = Depends(get_current_user)):
    now = datetime.now(timezone.utc)
    doc = {
        **payload.model_dump(),
        "user_id": current_user["id"],
        "created_at": now,
    }
    res = db["person"].insert_one(doc)
    return serialize_doc({"_id": res.inserted_id, **doc})

@app.get("/persons/{person_id}")
def get_person(person_id: str, current_user: Dict[str, Any] = Depends(get_current_user)):
    doc = db["person"].find_one({"_id": oid(person_id), "user_id": current_user["id"]})
    if not doc:
        raise HTTPException(404, detail="Person not found")
    return serialize_doc(doc)

@app.put("/persons/{person_id}")
def update_person(person_id: str, payload: PersonUpdate, current_user: Dict[str, Any] = Depends(get_current_user)):
    updates = {k: v for k, v in payload.model_dump().items() if v is not None}
    res = db["person"].find_one_and_update(
        {"_id": oid(person_id), "user_id": current_user["id"]},
        {"$set": {**updates, "updated_at": datetime.now(timezone.utc)}},
        return_document=True,
    )
    if not res:
        raise HTTPException(404, detail="Person not found")
    return serialize_doc(res)

@app.delete("/persons/{person_id}")
def delete_person(person_id: str, current_user: Dict[str, Any] = Depends(get_current_user)):
    # delete cascading simple (weights, goals, milestones)
    db["weightentry"].delete_many({"person_id": person_id})
    goals = db["goal"].find({"person_id": person_id})
    goal_ids = [str(g["_id"]) for g in goals]
    if goal_ids:
        db["milestone"].delete_many({"goal_id": {"$in": goal_ids}})
    res = db["person"].delete_one({"_id": oid(person_id), "user_id": current_user["id"]})
    if res.deleted_count == 0:
        raise HTTPException(404, detail="Person not found")
    return {"status": "deleted"}

# =====================
# Routes: Weight Entries
# =====================
@app.get("/persons/{person_id}/weights")
def list_weights(person_id: str, start: Optional[str] = None, end: Optional[str] = None, current_user: Dict[str, Any] = Depends(get_current_user)):
    # verify person ownership
    person = db["person"].find_one({"_id": oid(person_id), "user_id": current_user["id"]})
    if not person:
        raise HTTPException(404, detail="Person not found")
    q: Dict[str, Any] = {"person_id": person_id}
    if start or end:
        dt_q: Dict[str, Any] = {}
        if start:
            dt_q["$gte"] = datetime.fromisoformat(start)
        if end:
            dt_q["$lte"] = datetime.fromisoformat(end)
        q["datetime"] = dt_q
    docs = db["weightentry"].find(q).sort("datetime", 1)
    return [serialize_doc(d) for d in docs]

@app.post("/persons/{person_id}/weights")
def add_weight(person_id: str, payload: WeightEntryCreate, current_user: Dict[str, Any] = Depends(get_current_user)):
    person = db["person"].find_one({"_id": oid(person_id), "user_id": current_user["id"]})
    if not person:
        raise HTTPException(404, detail="Person not found")
    doc = {
        **payload.model_dump(),
        "person_id": person_id,
        "created_at": datetime.now(timezone.utc),
        "updated_at": datetime.now(timezone.utc),
    }
    res = db["weightentry"].insert_one(doc)
    return serialize_doc({"_id": res.inserted_id, **doc})

@app.put("/weights/{entry_id}")
def update_weight(entry_id: str, payload: WeightEntryUpdate, current_user: Dict[str, Any] = Depends(get_current_user)):
    entry = db["weightentry"].find_one({"_id": oid(entry_id)})
    if not entry:
        raise HTTPException(404, detail="Entry not found")
    # verify ownership via person
    person = db["person"].find_one({"_id": oid(entry["person_id"]), "user_id": current_user["id"]})
    if not person:
        raise HTTPException(403, detail="Not authorized")
    updates = {k: v for k, v in payload.model_dump().items() if v is not None}
    res = db["weightentry"].find_one_and_update(
        {"_id": oid(entry_id)},
        {"$set": {**updates, "updated_at": datetime.now(timezone.utc)}},
        return_document=True,
    )
    return serialize_doc(res)

@app.delete("/weights/{entry_id}")
def delete_weight(entry_id: str, current_user: Dict[str, Any] = Depends(get_current_user)):
    entry = db["weightentry"].find_one({"_id": oid(entry_id)})
    if not entry:
        raise HTTPException(404, detail="Entry not found")
    person = db["person"].find_one({"_id": oid(entry["person_id"]), "user_id": current_user["id"]})
    if not person:
        raise HTTPException(403, detail="Not authorized")
    db["weightentry"].delete_one({"_id": oid(entry_id)})
    return {"status": "deleted"}

# =====================
# Routes: Goals & Milestones
# =====================
@app.get("/persons/{person_id}/goals")
def list_goals(person_id: str, current_user: Dict[str, Any] = Depends(get_current_user)):
    person = db["person"].find_one({"_id": oid(person_id), "user_id": current_user["id"]})
    if not person:
        raise HTTPException(404, detail="Person not found")
    docs = db["goal"].find({"person_id": person_id}).sort("start_date", -1)
    res = []
    for d in docs:
        g = serialize_doc(d)
        g["milestones"] = [serialize_doc(m) for m in db["milestone"].find({"goal_id": g["id"]}).sort("target_date", 1)]
        res.append(g)
    return res

@app.post("/persons/{person_id}/goals")
def create_goal(person_id: str, payload: GoalCreate, current_user: Dict[str, Any] = Depends(get_current_user)):
    if payload.end_date <= payload.start_date:
        raise HTTPException(400, detail="End date must be after start date")
    person = db["person"].find_one({"_id": oid(person_id), "user_id": current_user["id"]})
    if not person:
        raise HTTPException(404, detail="Person not found")
    start_weight_kg: Optional[float] = None
    if payload.lock_start_to_first_log:
        first = db["weightentry"].find({"person_id": person_id, "datetime": {"$gte": datetime.combine(payload.start_date, datetime.min.time(), tzinfo=timezone.utc)}}).sort("datetime", 1).limit(1)
        first_list = list(first)
        if first_list:
            start_weight_kg = float(first_list[0]["weight_kg"])  # type: ignore
    doc = {
        "person_id": person_id,
        "start_date": payload.start_date,
        "end_date": payload.end_date,
        "target_weight_kg": payload.target_weight_kg,
        "start_weight_kg": start_weight_kg,
        "lock_start_to_first_log": payload.lock_start_to_first_log,
        "created_at": datetime.now(timezone.utc),
        "updated_at": datetime.now(timezone.utc),
    }
    res = db["goal"].insert_one(doc)
    return serialize_doc({"_id": res.inserted_id, **doc})

@app.put("/goals/{goal_id}")
def update_goal(goal_id: str, payload: GoalUpdate, current_user: Dict[str, Any] = Depends(get_current_user)):
    goal = db["goal"].find_one({"_id": oid(goal_id)})
    if not goal:
        raise HTTPException(404, detail="Goal not found")
    person = db["person"].find_one({"_id": oid(goal["person_id"]), "user_id": current_user["id"]})
    if not person:
        raise HTTPException(403, detail="Not authorized")
    updates = {k: v for k, v in payload.model_dump().items() if v is not None}
    if "start_date" in updates and "end_date" in updates and updates["end_date"] <= updates["start_date"]:
        raise HTTPException(400, detail="End date must be after start date")
    res = db["goal"].find_one_and_update(
        {"_id": oid(goal_id)},
        {"$set": {**updates, "updated_at": datetime.now(timezone.utc)}},
        return_document=True,
    )
    return serialize_doc(res)

@app.delete("/goals/{goal_id}")
def delete_goal(goal_id: str, current_user: Dict[str, Any] = Depends(get_current_user)):
    goal = db["goal"].find_one({"_id": oid(goal_id)})
    if not goal:
        raise HTTPException(404, detail="Goal not found")
    person = db["person"].find_one({"_id": oid(goal["person_id"]), "user_id": current_user["id"]})
    if not person:
        raise HTTPException(403, detail="Not authorized")
    db["milestone"].delete_many({"goal_id": str(goal["_id"])})
    db["goal"].delete_one({"_id": oid(goal_id)})
    return {"status": "deleted"}

@app.post("/goals/{goal_id}/milestones")
def add_milestone(goal_id: str, payload: MilestoneCreate, current_user: Dict[str, Any] = Depends(get_current_user)):
    goal = db["goal"].find_one({"_id": oid(goal_id)})
    if not goal:
        raise HTTPException(404, detail="Goal not found")
    person = db["person"].find_one({"_id": oid(goal["person_id"]), "user_id": current_user["id"]})
    if not person:
        raise HTTPException(403, detail="Not authorized")
    doc = {
        **payload.model_dump(),
        "goal_id": goal_id,
        "created_at": datetime.now(timezone.utc),
        "updated_at": datetime.now(timezone.utc),
    }
    res = db["milestone"].insert_one(doc)
    return serialize_doc({"_id": res.inserted_id, **doc})

@app.put("/milestones/{milestone_id}")
def update_milestone(milestone_id: str, payload: MilestoneUpdate, current_user: Dict[str, Any] = Depends(get_current_user)):
    ms = db["milestone"].find_one({"_id": oid(milestone_id)})
    if not ms:
        raise HTTPException(404, detail="Milestone not found")
    goal = db["goal"].find_one({"_id": oid(ms["goal_id"])})
    person = db["person"].find_one({"_id": oid(goal["person_id"]), "user_id": current_user["id"]}) if goal else None
    if not person:
        raise HTTPException(403, detail="Not authorized")
    updates = {k: v for k, v in payload.model_dump().items() if v is not None}
    res = db["milestone"].find_one_and_update(
        {"_id": oid(milestone_id)},
        {"$set": {**updates, "updated_at": datetime.now(timezone.utc)}},
        return_document=True,
    )
    return serialize_doc(res)

@app.delete("/milestones/{milestone_id}")
def delete_milestone(milestone_id: str, current_user: Dict[str, Any] = Depends(get_current_user)):
    ms = db["milestone"].find_one({"_id": oid(milestone_id)})
    if not ms:
        raise HTTPException(404, detail="Milestone not found")
    goal = db["goal"].find_one({"_id": oid(ms["goal_id"])})
    person = db["person"].find_one({"_id": oid(goal["person_id"]), "user_id": current_user["id"]}) if goal else None
    if not person:
        raise HTTPException(403, detail="Not authorized")
    db["milestone"].delete_one({"_id": oid(milestone_id)})
    return {"status": "deleted"}

# =====================
# Analytics helper endpoint
# =====================
@app.get("/persons/{person_id}/summary")
def person_summary(person_id: str, period: Optional[str] = None, start: Optional[str] = None, end: Optional[str] = None, current_user: Dict[str, Any] = Depends(get_current_user)):
    person = db["person"].find_one({"_id": oid(person_id), "user_id": current_user["id"]})
    if not person:
        raise HTTPException(404, detail="Person not found")

    # Determine range
    start_dt: Optional[datetime] = None
    end_dt: Optional[datetime] = None
    now = datetime.now(timezone.utc)
    if period in {"7", "30", "90"}:
        end_dt = now
        start_dt = now - timedelta(days=int(period))
    if start:
        start_dt = datetime.fromisoformat(start)
    if end:
        end_dt = datetime.fromisoformat(end)

    q: Dict[str, Any] = {"person_id": person_id}
    if start_dt or end_dt:
        dt_q: Dict[str, Any] = {}
        if start_dt:
            dt_q["$gte"] = start_dt
        if end_dt:
            dt_q["$lte"] = end_dt
        q["datetime"] = dt_q
    entries = list(db["weightentry"].find(q).sort("datetime", 1))
    entries_ser = [serialize_doc(e) for e in entries]

    latest = entries[-1] if entries else None
    seven_days_ago = now - timedelta(days=7)
    past7 = list(db["weightentry"].find({"person_id": person_id, "datetime": {"$lte": now, "$gte": seven_days_ago}}).sort("datetime", 1))
    change7 = None
    if past7:
        first7 = past7[0]
        last7 = past7[-1]
        change7 = float(last7.get("weight_kg")) - float(first7.get("weight_kg"))

    # Fetch most recent active goal if any
    goals = list(db["goal"].find({"person_id": person_id}).sort("start_date", -1).limit(1))
    goal = serialize_doc(goals[0]) if goals else None
    milestones = []
    if goal:
        milestones = [serialize_doc(m) for m in db["milestone"].find({"goal_id": goal["id"]}).sort("target_date", 1)]

    # Simple linear trend (least squares)
    trend = None
    if len(entries) >= 2:
        xs = [(e["datetime"].timestamp()) for e in entries]
        ys = [float(e["weight_kg"]) for e in entries]
        n = len(xs)
        x_mean = sum(xs) / n
        y_mean = sum(ys) / n
        denom = sum((x - x_mean) ** 2 for x in xs) or 1.0
        slope = sum((xs[i] - x_mean) * (ys[i] - y_mean) for i in range(n)) / denom
        intercept = y_mean - slope * x_mean
        trend = {
            "slope": slope,
            "intercept": intercept,
            "start": {"x": datetime.fromtimestamp(xs[0], tz=timezone.utc).isoformat(), "y": slope * xs[0] + intercept},
            "end": {"x": datetime.fromtimestamp(xs[-1], tz=timezone.utc).isoformat(), "y": slope * xs[-1] + intercept},
        }

    return {
        "person": serialize_doc(person),
        "entries": entries_ser,
        "latest": serialize_doc(latest) if latest else None,
        "change7": change7,
        "goal": goal,
        "milestones": milestones,
        "trend": trend,
    }


if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)
