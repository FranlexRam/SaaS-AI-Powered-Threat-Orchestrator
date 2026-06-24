from sqlalchemy import Column, Integer, String, DateTime, ForeignKey, Boolean
from sqlalchemy.orm import declarative_base, relationship
from datetime import datetime

Base = declarative_base()

class Tenant(Base):
    __tablename__ = 'tenants'
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, unique=True, index=True)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)

class SaktiUser(Base):
    __tablename__ = 'sakti_users'
    id = Column(Integer, primary_key=True, index=True)
    tenant_id = Column(Integer, ForeignKey('tenants.id'), nullable=False)
    username = Column(String, unique=True, index=True)
    password_hash = Column(String) # Aquí implementaremos Bcrypt más adelante
    role = Column(String, default="USER") # RBAC: "SUPERADMIN", "ADMIN", "USER"
    
    tenant = relationship("Tenant")

class APIKey(Base):
    __tablename__ = 'api_keys'
    id = Column(Integer, primary_key=True, index=True)
    tenant_id = Column(Integer, ForeignKey('tenants.id'), nullable=False)
    key_hash = Column(String, unique=True, index=True) # Nunca guardamos la API Key en texto plano
    is_active = Column(Boolean, default=True)

class SecurityEvent(Base):
    __tablename__ = 'security_events'
    id = Column(Integer, primary_key=True, index=True)
    tenant_id = Column(Integer, ForeignKey('tenants.id'), nullable=False)
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)
    attack_type = Column(String) # Ej: SQLi, RCE, XSS
    risk_level = Column(String) # LOW, MEDIUM, HIGH, CRITICAL
    source_ip = Column(String)
    action_taken = Column(String) # Ej: "Blocked", "Logged"
    
    tenant = relationship("Tenant")