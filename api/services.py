# Standard Library Imports
import random
import string
from datetime import datetime, timedelta
import os
# Django Imports
from django.core.mail import send_mail
from django.conf import settings
from django.contrib.auth.hashers import make_password

# Third-Party Imports
from pymongo import MongoClient

# Assuming student_collection is your MongoDB collection
MONGO_URI=os.environ.get('MONGO_URI')
print(MONGO_URI)
MONGODB_TIMEOUT_MS = os.environ.get("MONGODB_TIMEOUT_MS")
client = MongoClient(MONGO_URI,serverSelectionTimeoutMS=MONGODB_TIMEOUT_MS)

db = client["CCE"]
student_collection = db["students"]

def generate_reset_token(length=6):
    """
    Generates a random numeric reset token.

    Parameters:
    - length (int): The length of the generated token (default is 6).

    Returns:
    - str: A string containing a randomly generated numeric token.
    """
    return ''.join(random.choices(string.digits, k=length))

def request_password_reset(email):
    """
    Handle the password reset request by generating a numeric OTP token and emailing it to the user.

    Parameters:
    - email (str): The email address of the student requesting a password reset.

    Returns:
    - dict: A message indicating success or failure.
    - int: The corresponding HTTP status code.
    """
    # Convert email to lowercase for case-insensitive comparison
    email = email.lower()

    user = student_collection.find_one({"email": email})
    if not user:
        return {"error": "Email not found"}, 400

    reset_token = generate_reset_token()  # Now generates a numeric OTP
    expiration_time = datetime.utcnow() + timedelta(hours=1)

    student_collection.update_one(
        {"email": email},
        {"$set": {
            "password_reset_token": reset_token,
            "password_reset_expires": expiration_time
        }}
    )

    try:
        send_mail(
            'Password Reset Request',
            f'Your OTP for password reset is: {reset_token}',
            settings.DEFAULT_FROM_EMAIL,
            [email],
        )
        return {"message": "Password reset OTP sent to your email"}, 200
    except Exception as e:
        return {"error": f"Failed to send email: {str(e)}"}, 500

def verify_reset_token(email, token):
    """
    Verify the provided numeric OTP for password reset.

    Parameters:
    - email (str): The email associated with the reset token.
    - token (str): The numeric OTP provided by the student.

    Returns:
    - dict: A message indicating whether the token is valid or not.
    - int: The corresponding HTTP status code.
    """
    student_user = student_collection.find_one({"email": email})
    if not student_user:
        return {"error": "No account found with this email"}, 404

    if student_user.get("password_reset_token") == token:
        return {"message": "OTP verification successful"}, 200
    return {"error": "Invalid OTP"}, 403

def reset_student_password(email, new_password, reset_token):
    """
    Resets the student's password after validating the reset token.

    Parameters:
    - email (str): The email of the student resetting their password.
    - new_password (str): The new password provided by the student.
    - reset_token (str): The reset token submitted for verification.

    Returns:
    - tuple (dict, int): Response message and HTTP status code.
    """
    email = email.lower()

    # Find the student by email
    student = student_collection.find_one({"email": email})
    if not student:
        return {"error": "Student not found"}, 404

    # Validate reset token
    stored_token = student.get("password_reset_token")
    token_expiry = student.get("password_reset_expires")

    if not stored_token or stored_token != reset_token:
        return {"error": "Invalid or expired reset token"}, 403

    # Check if the token has expired
    if token_expiry and datetime.utcnow() > token_expiry:
        return {"error": "Reset token has expired. Please request a new one."}, 403

    # Hash the new password
    hashed_password = make_password(new_password)

    # Ensure hashed password starts with "pbkdf2_sha256$"
    if not hashed_password.startswith("pbkdf2_sha256$"):
        return {"error": "Failed to hash the password correctly."}, 500

    # Update the password in MongoDB
    result = student_collection.update_one(
        {"email": email},
        {"$set": {
            "password": hashed_password,
            "password_reset_token": None,  # Clear reset token
            "password_reset_expires": None  # Clear expiration time
        }}
    )

    if result.modified_count == 0:
        return {"error": "Failed to update the password in MongoDB."}, 500

    return {"message": "Password reset successfully"}, 200