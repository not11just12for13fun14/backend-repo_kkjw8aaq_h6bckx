from pydantic import BaseModel, Field, EmailStr, ConfigDict
from typing import Optional, List
from datetime import date, datetime

# User accounts
class User(BaseModel):
    model_config = ConfigDict(extra='ignore')
    email: EmailStr = Field(..., description="Email address")
    password_hash: str = Field(..., description="BCrypt hash of the user's password")
    created_at: Optional[datetime] = None

# Profiles managed by a user
class Person(BaseModel):
    model_config = ConfigDict(extra='ignore')
    user_id: str = Field(..., description="Owner user id (stringified ObjectId)")
    name: str
    nickname: Optional[str] = None
    starting_weight_kg: Optional[float] = Field(None, ge=20, le=300)
    height_cm: Optional[float] = Field(None, ge=50, le=250)
    date_of_birth: Optional[date] = None
    created_at: Optional[datetime] = None

# Individual weight logs
class Weightentry(BaseModel):
    model_config = ConfigDict(extra='ignore')
    person_id: str
    datetime: datetime
    weight_kg: float = Field(..., ge=20, le=300, description="Weight in kg, one decimal recommended")
    note: Optional[str] = None
    created_at: Optional[datetime] = None

# Goal per person
class Goal(BaseModel):
    model_config = ConfigDict(extra='ignore')
    person_id: str
    start_date: date
    end_date: date
    start_weight_kg: Optional[float] = Field(None, ge=20, le=300)
    target_weight_kg: float = Field(..., ge=20, le=300)
    lock_start_to_first_log: Optional[bool] = False
    created_at: Optional[datetime] = None

# Milestones within a goal
class Milestone(BaseModel):
    model_config = ConfigDict(extra='ignore')
    goal_id: str
    title: str
    target_date: date
    target_weight_kg: float = Field(..., ge=20, le=300)
    note: Optional[str] = None
    created_at: Optional[datetime] = None
