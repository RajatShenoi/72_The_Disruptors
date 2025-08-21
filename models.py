from sqlalchemy import Column, Integer, String
from sqlalchemy.ext.declarative import declarative_base
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin

db = SQLAlchemy()

class User(db.Model, UserMixin):
    __tablename__ = 'users'

    id = Column(Integer, primary_key=True, autoincrement=True)
    email = Column(String(255), unique=True, nullable=False)
    hashed_password = Column(String(255), nullable=False)

class Queries(db.Model):
    __tablename__ = 'queries'

    id = Column(Integer, primary_key=True, autoincrement=True)
    performance = Column(String, nullable=False)
    security = Column(String, nullable=False)