from flask_sqlalchemy import SQLAlchemy
from sqlalchemy_serializer import SerializerMixin 
from werkzeug.security import generate_password_hash, check_password_hash
from database import db

# Junction Table for User and Role
user_roles = db.Table('user_roles',
    db.Column('user_id', db.Integer, db.ForeignKey('user.id'), primary_key=True),
    db.Column('role_id', db.Integer, db.ForeignKey('role.id'), primary_key=True)
)

class User(db.Model, SerializerMixin):
    __tablename__ = 'user'
    
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    
    roles = db.relationship('Role', secondary=user_roles, backref=db.backref('users', lazy='dynamic'))
    serialize_rules = ('-password_hash',)  # Exclude sensitive data

    def __init__(self, username, email, password):
        self.username = username
        self.email = email
        self.set_password(password)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def has_role(self, role_name):
        """Check if the user has a particular role"""
        return any(role.name == role_name for role in self.roles)

class Role(db.Model, SerializerMixin):
    __tablename__ = 'role'

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80), unique=True)

class Organization(db.Model, SerializerMixin):
    __tablename__ = 'organization'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    name = db.Column(db.String(255), nullable=False)
    description = db.Column(db.Text)
    contact_information = db.Column(db.String(255))
    status = db.Column(db.String(50), default="Pending")
    
    owner = db.relationship('User', backref='organizations')
    donations = db.relationship('Donation', backref='organization')
    stories = db.relationship('Story', backref='organization')
    beneficiaries = db.relationship('Beneficiary', backref='organization')

class Donation(db.Model, SerializerMixin):
    __tablename__ = 'donation'

    id = db.Column(db.Integer, primary_key=True)
    donor_user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    organization_id = db.Column(db.Integer, db.ForeignKey('organization.id'), nullable=False)
    amount = db.Column(db.Numeric(10, 2), nullable=False)
    donation_type = db.Column(db.String(50), nullable=False)
    anonymous = db.Column(db.Boolean, default=False)
    date = db.Column(db.Date, nullable=False)
    
    donor = db.relationship('User', backref='donations')

class Story(db.Model, SerializerMixin):
    __tablename__ = 'story'

    id = db.Column(db.Integer, primary_key=True)
    organization_id = db.Column(db.Integer, db.ForeignKey('organization.id'), nullable=False)
    title = db.Column(db.String(255), nullable=False)
    content = db.Column(db.Text, nullable=False)
    images = db.Column(db.String(255))
    date_created = db.Column(db.Date, nullable=False)

class Beneficiary(db.Model, SerializerMixin):
    __tablename__ = 'beneficiary'

    id = db.Column(db.Integer, primary_key=True)
    organization_id = db.Column(db.Integer, db.ForeignKey('organization.id'), nullable=False)
    name = db.Column(db.String(255), nullable=False)
    description = db.Column(db.Text)
    inventory_received = db.Column(db.Text)
    
    inventory_items = db.relationship('Inventory', backref='beneficiary')

class Inventory(db.Model, SerializerMixin):
    __tablename__ = 'inventory'

    id = db.Column(db.Integer, primary_key=True)
    beneficiary_id = db.Column(db.Integer, db.ForeignKey('beneficiary.id'), nullable=False)
    description = db.Column(db.String(255), nullable=False)
    quantity = db.Column(db.Integer, nullable=False)
    date_received = db.Column(db.Date, nullable=False)
