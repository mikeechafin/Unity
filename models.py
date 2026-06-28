# models.py
from flask_login import UserMixin

class User(UserMixin):
    def __init__(self, id):
        self.id = id
        self.is_superuser = id == 'maamd'  # Adjust as needed (from config/DB)
