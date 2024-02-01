from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
from flask_login import UserMixin

db = SQLAlchemy()


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(60), nullable=False)
    consumptions = db.relationship('Consumption', backref='user', lazy=True)
    is_admin = db.Column(db.Boolean, default=False)
    def __repr__(self):
        return f'<User {self.username}>'

class PantryItem(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    price = db.Column(db.Float, nullable=False)
    consumptions = db.relationship('Consumption', backref='item', lazy=True)
    stock = db.Column(db.Integer, default=0)

    def __repr__(self):
        return f'<PantryItem {self.title}>'

class Consumption(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    item_id = db.Column(db.Integer, db.ForeignKey('pantry_item.id'), nullable=False)
    quantity = db.Column(db.Integer, default=1)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

    def __repr__(self):
        return f'<Consumption {self.user_id} {self.item_id}>'
