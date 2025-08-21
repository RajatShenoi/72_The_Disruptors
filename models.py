from sqlalchemy import Column, ForeignKey, Integer, String
from sqlalchemy.ext.declarative import declarative_base
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin

db = SQLAlchemy()

class User(db.Model, UserMixin):
    __tablename__ = 'users'

    id = Column(Integer, primary_key=True, autoincrement=True)
    email = Column(String(255), unique=True, nullable=False)
    hashed_password = Column(String(255), nullable=False)
    queries = db.relationship('Queries', backref='user', lazy=True)

class Queries(db.Model):
    __tablename__ = 'queries'

    id = Column(Integer, primary_key=True, autoincrement=True)
    created_at = Column(db.DateTime, server_default=db.func.now(), nullable=False)
    user_id = Column(Integer, ForeignKey('users.id'), nullable=False)
    url = Column(String, nullable=False)
    status = Column(Integer, nullable=False) # 0 in progress, 1 completed, 2 failed, 3 queued
    scores = Column(String, nullable=False)
    performance = Column(String, nullable=False)
    security = Column(String, nullable=False)