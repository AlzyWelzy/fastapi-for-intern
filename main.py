from fastapi import FastAPI, HTTPException, Depends, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from sqlalchemy import Boolean, create_engine, Column, Integer, String
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session
from pydantic import BaseModel, EmailStr
from typing import List, Optional
from passlib.context import CryptContext
import jwt
from datetime import datetime, timedelta
from pwdlib import PasswordHash

# Security and authentication setup

with open("private.pem", "r") as f:
    PRIVATE_KEY = f.read()

with open("public.pem", "r") as f:
    PUBLIC_KEY = f.read()

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
ALGORITHM = "RS512"
ACCESS_TOKEN_EXPIRE_MINUTES = 30
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")
app = FastAPI(title="FastAPI with SQLAlchemy Example")

# database setup
engine = create_engine("sqlite:///./test.db", connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


class User(Base):
    __tablename__ = "users"
    ROLES = ["user", "admin"]
    id = Column(Integer, primary_key=True, index=True)
    email = Column(String(100), unique=True, index=True, nullable=False)
    name = Column(String(100), nullable=False)
    role = Column(String(50), default="user", nullable=False)
    hashed_password = Column(String, nullable=False)
    is_active = Column(Boolean, default=True, nullable=False)


Base.metadata.create_all(bind=engine)


class UserCreate(BaseModel):
    email: str
    name: str
    role: Optional[str] = "user"
    password: str

    # class Config:
    #     orm_mode = True


class UserUpdate(BaseModel):
    email: Optional[EmailStr] = None
    name: Optional[str] = None
    role: Optional[str] = None


class UserResponse(BaseModel):
    id: int
    email: str
    name: str
    role: str
    is_active: bool

    class Config:
        # orm_mode = True
        from_attributes = True


class UserLogin(BaseModel):
    email: str
    password: str


class Token(BaseModel):
    access_token: str
    token_type: str


class TokenData(BaseModel):
    email: Optional[str] = None
    role: Optional[str] = None
    name: Optional[str] = None


def verify_password(plain_password, hashed_password) -> bool:
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password) -> str:
    return pwd_context.hash(password)


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, PRIVATE_KEY, algorithm=ALGORITHM)
    return encoded_jwt


def verify_token(
    token: str,
):
    try:
        payload = jwt.decode(token, PUBLIC_KEY, algorithms=[ALGORITHM])
        email: str = payload.get("sub")
        role: str = payload.get("role")
        name: str = payload.get("name")
        if email is None or role is None or name is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token",
                headers={"WWW-Authenticate": "Bearer"},
            )
        token_data = TokenData(email=email, role=role, name=name)
    except jwt.PyJWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return token_data


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


get_db()


def get_current_user(
    token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)
):
    token_data = verify_token(token)
    user = db.query(User).filter(User.email == token_data.email).first()
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return user


def get_current_active_user(current_user: User = Depends(get_current_user)):
    if not current_user.is_active:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Inactive user"
        )
    return current_user


@app.post("/register", response_model=UserResponse)
def register_user(user: UserCreate, db: Session = Depends(get_db)):
    if db.query(User).filter(User.email == user.email).first():
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Email already registered"
        )
    if user.role not in User.ROLES:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid role"
        )
    hashed_password = get_password_hash(user.password)
    db_user = User(
        email=user.email,
        name=user.name,
        role=user.role,
        hashed_password=hashed_password,
    )

    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    return db_user


@app.post("/token", response_model=Token)
def login_for_access_token(
    form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)
):
    user = db.query(User).filter(User.email == form_data.username).first()
    if not user or not verify_password(form_data.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.email, "role": user.role, "name": user.name},
        expires_delta=access_token_expires,
    )
    return {"access_token": access_token, "token_type": "bearer"}


@app.get("/me", response_model=UserResponse)
def get_current_user_profile(
    current_user: User = Depends(get_current_active_user),
):
    return current_user


@app.get("/verify-token")
def verify_token_endpoint(token: str = Depends(get_current_active_user)):
    return {
        "detail": "Token is valid",
        "user": token.email,
        "role": token.role,
        "name": token.name,
    }


@app.get("/")
def root():
    return {"Hello": "World"}


@app.get("/users/", response_model=List[UserResponse])
def get_users(
    current_user: User = Depends(get_current_active_user), db: Session = Depends(get_db)
):
    users = db.query(User).all()
    return users


@app.get("/users/{user_id}", response_model=UserResponse)
def get_user(
    user_id: int,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db),
):
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="User not found"
        )
    return user


@app.post("/users/", response_model=UserResponse)
def create_user(
    user: UserCreate,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db),
):
    if db.query(User).filter(User.email == user.email).first():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="Email already registered"
        )
    if user.role not in User.ROLES:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid role"
        )
    hashed_password = get_password_hash(user.password)
    db_user = User(
        email=user.email,
        name=user.name,
        role=user.role,
        hashed_password=hashed_password,
    )

    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    return db_user


@app.patch("/users/{user_id}", response_model=UserResponse)
def update_user(
    user_id: int,
    user: UserUpdate,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db),
):
    db_user = db.query(User).filter(User.id == user_id).first()
    if not db_user:
        raise HTTPException(status_code=404, detail="User not found")
    if (
        user.email
        and db.query(User).filter(User.email == user.email, User.id != user_id).first()
    ):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="Email already registered"
        )
    if user.role and user.role not in User.ROLES:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid role"
        )

    # db_user.email = user.email or db_user.email
    # db_user.name = user.name or db_user.name
    # db_user.role = user.role or db_user.role

    # db.commit()
    # db.refresh(db_user)
    # return db_user

    for field, value in user.model_dump(exclude_unset=True).items():
        setattr(db_user, field, value)
    db.commit()
    db.refresh(db_user)
    return db_user


@app.delete("/users/{user_id}")
def delete_user(
    user_id: int,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db),
):

    db_user = db.query(User).filter(User.id == user_id).first()
    if not db_user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="User not found"
        )
    if db_user.id == current_user.id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="Cannot delete yourself"
        )
    db.delete(db_user)
    db.commit()
    return {"detail": "User deleted"}


{
    "access_token": "eyJhbGciOiJSUzUxMiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJzdHJpbmdAc3IiLCJyb2xlIjoidXNlciIsIm5hbWUiOiJzdHJpbmciLCJleHAiOjE3Nzk2MzY2MjZ9.OsAALUsVkX6WaeeXUTYVNCHVbXe8YcQSI1LVNyHed7gcttM3tAwwQoQfNaMdOx3ia1lGdBiaFiF7lX3snDd-j86D39YY17UeKM26og4lt4EW9TZ6tqwA5349iE-rE6Jwkt1IyJMUmUCFUnH9XgXR3INb4edaT0h6Rzi4Go-L4b19oKRQD-zIkyNJGDhTyiA9mRoDGVfMBWIBfOHI_SWzxMS7FLXm4HXquhAxf-XLwWgkx2c4_I9pEUdbQ929QZJj2m83yxW62asFhqdWN7bdZhEmVHbwrDJIEbqh4Xg-copzkkGuD-QOLLGTTKXHJS8g9lP4-cXUbqacE3OjyJu6mFy1R4XebhcPX5SLsBLzShXbW2ZbXrV9gZVxUIOpbEXW3py82aXppHNoWiJn8znD0S-lLhw75q8Ie7Y0rS3xyX8uSzDNJmHast6GuMWzEt188Q5guuEumFUa9rdOSKFa7HOPo_w8tOBwRNvaAxGdJ6LBHLilSaRkgVGuYVU_Q09nVGoQ22XRmMr8OoQKx_j3oiFLM8ppVyPGk1fTEekybxeIs4u39M8L495WSHvzW3Lp8FRCAu7VILoumFZhzBldUkYmQXTubSTDF19UNBzjxxzDAfpPpxbGKnsyWMpl_ovBLiBdswtiVq380pKiUpAUcPgSu5inMhgXHlt9Y9hqcoY",
    "token_type": "bearer",
}
