# Standard Library Imports
import json
import os
import re
import random
import string
import traceback
import logging
import base64
import smtplib
from datetime import datetime, timedelta, timezone
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

# Third-Party Imports
import jwt
import pytz
from pymongo import MongoClient
import bleach
from bson import ObjectId, Binary
import pandas as pd
from django.core.mail import send_mail
from django.conf import settings
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from rest_framework import status

# Django Imports
from django.http import JsonResponse
from django.utils import timezone
from google.oauth2 import id_token
from django.core.validators import validate_email
from django.core.exceptions import ValidationError
from google.auth.transport import requests as google_requests
from django.contrib.auth.hashers import make_password, check_password
from django.views.decorators.csrf import csrf_exempt
from .services import request_password_reset, verify_reset_token, reset_student_password

from dotenv import load_dotenv
load_dotenv()


from django.http import JsonResponse
import functools

def handle_exceptions(view_func):
    """
    Decorator to handle exceptions in Django views.
    Returns a JSON response with an error message on exception.
    """
    @functools.wraps(view_func)
    def wrapper(request, *args, **kwargs):
        try:
            return view_func(request, *args, **kwargs)
        except Exception as e:
            return JsonResponse({"error": str(e)}, status=400)
    return wrapper


def generate_tokens(student_user):
    """
    Generates a JWT access token for a student user.

    The token contains the student user's identifier, an expiration time of 600 minutes,
    and the issued-at timestamp. It is signed using a secret key and a specified algorithm.

    Parameters:
    student_user (str): The unique identifier of the student user.

    Returns:
    dict: A dictionary containing the generated JWT token.
    """
    
    access_payload = {
        "student_user": str(student_user),
        "exp": (datetime.utcnow() + timedelta(minutes=600)).timestamp(),  # Expiration in 600 minutes
        "iat": datetime.utcnow().timestamp(),  # Issued at current time
    }
    token = jwt.encode(access_payload, settings.JWT_SECRET, algorithm=settings.JWT_ALGORITHM)
    return {"jwt": token}


# MongoDB connection
client = MongoClient(settings.MONGO_URI)
db = client["CCE"]
student_collection = db["students"]
superadmin_collection = db["superadmin"]
admin_collection = db["admin"]
job_collection = db["jobs"]
internship_collection = db['internships']
contactus_collection = db["contact_us"]
achievement_collection = db['student_achievement']
study_material_collection = db['studyMaterial']
superadmin_collection = db['superadmin']
message_collection = db['message']
exam_collection = db['exam']
deleted_exam_collection = db['deleted_exam']
# Dictionary to track failed login attempts
failed_login_attempts = {}
lockout_duration = timedelta(minutes=2)  # Time to lock out after 3 failed attempts

# function to check if password is strong
def is_strong_password(password):
    """
    Checks whether a given password meets strength requirements.

    The password must:
    - Be at least 8 characters long.
    - Contain at least one uppercase letter.
    - Contain at least one lowercase letter.
    - Contain at least one digit.
    - Contain at least one special character (@, $, !, %, *, ?, &, #).

    Parameters:
    password (str): The password to be validated.

    Returns:
    tuple:
        - (bool): True if the password meets all requirements, otherwise False.
        - (str): An error message if the password is weak, otherwise an empty string.
    """
    if len(password) < 8:
        return False, "Password must be at least 8 characters long."
    if not re.search(r"[A-Z]", password):
        return False, "Password must include at least one uppercase letter."
    if not re.search(r"[a-z]", password):
        return False, "Password must include at least one lowercase letter."
    if not re.search(r"[0-9]", password):
        return False, "Password must include at least one digit."
    if not re.search(r"[@$!%*?&#]", password):
        return False, "Password must include at least one special character."
    return True, ""

# Function to send email
def send_email(to_email, subject, body):
    """
    Sends an email using the configured SMTP server.

    Parameters:
    to_email (str): The recipient's email address.
    subject (str): The subject of the email.
    body (str): The body of the email.

    Returns:
    None

    Exceptions:
    Prints an error message if the email fails to send.
    """
    msg = MIMEMultipart()
    msg["From"] = settings.EMAIL_HOST_USER
    msg["To"] = to_email
    msg["Subject"] = subject

    msg.attach(MIMEText(body, "plain"))

    try:
        # Connect to the SMTP server
        server = smtplib.SMTP(settings.EMAIL_HOST, settings.EMAIL_PORT)
        server.starttls()  # Secure the connection
        server.login(
            settings.EMAIL_HOST_USER, settings.EMAIL_HOST_PASSWORD
        )  # Login with credentials
        text = msg.as_string()
        server.sendmail(settings.EMAIL_HOST_USER, to_email, text)  # Send the email
        server.quit()  # Close the connection

    except Exception as e:
        print(f"Error sending email: {str(e)}")

# Function to send confirmation email
def send_confirmation_email(to_email, name, password):
    """
    Sends a confirmation email to a newly created student account.

    Parameters:
    to_email (str): The recipient's email address.
    name (str): The student's username.
    password (str): The student's temporary or generated password.

    Returns:
    None
    """
    subject = "Student Account Created"
    body = f"""
    Your Student account has been successfully created on the CCE platform.
    Username: {name}
    Password: {password}
    Please keep your credentials safe and secure.
    """
    send_email(to_email, subject, body)


# Student Signup
@csrf_exempt
@handle_exceptions  # Apply the error handler
def student_signup(request):
    """
    Handles student user signup by creating a new student record.

    This function:
    - Parses student details from the request.
    - Validates email format and checks for duplicate emails.
    - Ensures the password meets security requirements.
    - Hashes the password before storing it in the database.
    - Saves the student details in the database.
    - Sends a confirmation email to the student with login credentials.

    Parameters:
    request (HttpRequest): The HTTP request object containing student signup details.

    Returns:
    JsonResponse: A response indicating success or failure.
    """
    if request.method == "POST":
        try:
            data = json.loads(request.body)
            name = data.get("name")
            email = data.get("email")
            department = data.get("department")
            year = data.get("year")
            college_name = data.get("college_name")
            password = data.get("password")
            mobile_number = data.get("mobileNumber")

            # Convert email to lowercase before checking
            if email:
                email = email.lower()
                
                # Check email length
                if len(email) > 100:
                    return JsonResponse(
                        {"error": "Email address is too long (max 100 characters)."}, status=400
                    )

                # Validate email format using Django's built-in validator
                try:
                    validate_email(email)
                except ValidationError:
                    return JsonResponse({"error": "Invalid email format."}, status=400)

                # Check if the email belongs to the college domain
                if not re.match(r"^[a-zA-Z0-9._%+-]+@sns\.[a-zA-Z]{2,}$", email):
                    return JsonResponse(
                        {"error": "Please enter a valid SNS college email (e.g., example@sns.ac.in)."}, status=400
                    )

            # Check if the email already exists
            if student_collection.find_one({"email": email}):
                return JsonResponse(
                    {"error": "A student with this email already exists."}, status=400
                )

            # Check if the password is strong
            is_valid, error_message = is_strong_password(password)
            if not is_valid:
                return JsonResponse({"error": error_message}, status=400)

            # Hash the password
            hashed_password = make_password(password)

            # Create the student user document
            student_user = {
                "name": name,
                "department": department,
                "year": year,
                "college_name": college_name,
                "email": email,
                "password": hashed_password,
                "mobile_number": mobile_number,
                "status": "active",  # Default status
                "last_login": None,  # No login yet
                "created_at": datetime.utcnow(),  # Account creation timestamp
            }

            # Insert the document into the collection
            student_collection.insert_one(student_user)

            # Send confirmation email with username and password
            send_confirmation_email(email, name, password)

            return JsonResponse(
                {"message": "Student user created successfully, confirmation email sent."}, status=201
            )
        except Exception as e:
            return JsonResponse({"error": str(e)}, status=400)
    else:
        return JsonResponse({"error": "Invalid request method"}, status=400)
    
studentcollection = db["students"]
@csrf_exempt
def bulk_student_signup(request):
    if request.method == "POST":
        try:
            if 'file' not in request.FILES:
                return JsonResponse({"error": "No file provided. Please select a file to upload."}, status=400)

            file = request.FILES['file']
            file_extension = file.name.split('.')[-1].lower()

            if file_extension == 'csv':
                df = pd.read_csv(file)
            elif file_extension in ['xlsx', 'xls']:
                df = pd.read_excel(file)
            else:
                return JsonResponse({"error": "Unsupported file format. Please upload CSV or XLSX."}, status=400)

            required_columns = ["name", "email", "password", "department", "year", "college_name", "mobileNumber"]
            missing_columns = [col for col in required_columns if col not in df.columns]

            if missing_columns:
                return JsonResponse({"error": f"Missing columns: {', '.join(missing_columns)}"}, status=400)

            if df.empty:
                return JsonResponse({"error": "The uploaded file is empty."}, status=400)

            success_count = 0
            errors = []

            valid_years = ["I", "II", "III", "IV"]

            for index, row in df.iterrows():
                try:
                    missing_fields = [field for field in required_columns if pd.isnull(row[field])]
                    if missing_fields:
                        errors.append({"row": index + 2, "error": f"Missing fields: {', '.join(missing_fields)}"})
                        continue

                    if "@sns" not in row['email']:
                        errors.append({"row": index + 2, "error": "Invalid email format. Must be an @sns email."})
                        continue

                    if row['year'] not in valid_years:
                        errors.append({"row": index + 2, "error": f"Invalid year: {row['year']}. Must be I, II, III, or IV."})
                        continue

                    if student_collection.find_one({"email": row['email']}):
                        errors.append({"row": index + 2, "error": f"Email already exists: {row['email']}"})
                        continue

                    is_valid, error_message = is_strong_password(row['password'])
                    if not is_valid:
                        errors.append({"row": index + 2, "error": error_message})
                        continue

                    hashed_password = make_password(row['password'])

                    student_user = {
                        "name": row['name'],
                        "department": row['department'],
                        "year": row['year'],
                        "college_name": row['college_name'],
                        "email": row['email'],
                        "password": hashed_password,
                        "mobile_number": str(row['mobileNumber']),
                        "status": "active",
                        "last_login": None,
                        "created_at": datetime.utcnow(),
                    }

                    studentcollection.insert_one(student_user)
                    success_count += 1

                except Exception as e:
                    errors.append({"row": index + 2, "error": str(e)})

            response_data = {
                "success_count": success_count,
                "error_count": len(errors),
                "errors": errors if errors else None
            }

            return JsonResponse(response_data, status=201 if success_count > 0 else 400)

        except Exception as e:
            return JsonResponse({"error": str(e)}, status=500)

    return JsonResponse({"error": "Invalid request method."}, status=400)

# Check lockout status
def check_lockout_status(email):
     """
     Checks the lockout status for a given email.
 
     Parameters:
     email (str): The email address to check.
 
     Returns:
     tuple: A tuple containing a boolean indicating if the account is locked out and an error message if it is.
     """
     if email in failed_login_attempts:
         lockout_data = failed_login_attempts[email]
         if (
             lockout_data["count"] >= 3
             and datetime.now() < lockout_data["lockout_until"]
         ):
             return True, "Too many failed attempts. Please try again after 2 minutes."
     return False, ""
 
 # Update failed attempts
def update_failed_attempts(email):
     """
     Updates the failed login attempts for a given email.
 
     Parameters:
     email (str): The email address to update.
     """
     if email not in failed_login_attempts:
         failed_login_attempts[email] = {"count": 1, "lockout_until": None}
     else:
         failed_login_attempts[email]["count"] += 1
         if failed_login_attempts[email]["count"] >= 3:
             failed_login_attempts[email]["lockout_until"] = (
                 datetime.now() + lockout_duration
             )
 

import re
from django.utils.html import escape  # For sanitizing inputs

@csrf_exempt
@handle_exceptions  # Apply the error handler
def student_login(request):
    """
    Handles student login authentication.

    Parameters:
    request (HttpRequest): The HTTP request object containing student login details.

    Returns:
    JsonResponse: A response containing either a JWT token (on success) or an error message (on failure).
    """
    if request.method == "POST":
        try:
            data = json.loads(request.body)
            email = data.get("email", "").strip().lower()
            password = data.get("password", "").strip()

            # Email validation (Sanitization + Validation)
            if not re.match(r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$", email):
                return JsonResponse({"error": "Invalid email format"}, status=400)

            if len(email) > 100:
                return JsonResponse({"error": "Email address is too long"}, status=400)

           # Sanitize input to remove potentially harmful characters
            email = bleach.clean(email)
            password = bleach.clean(password)

            # Check lockout status
            is_locked_out, lockout_message = check_lockout_status(email)
            if is_locked_out:
                return JsonResponse({"error": lockout_message}, status=403)

            # Find the student user by email (Case-insensitive)
            student_user = student_collection.find_one({"email": {"$eq": email}})
            if not student_user:
                return JsonResponse(
                    {"error": "No account found with this email"}, status=404
                )

            # Check if the account is active
            if student_user.get("status") != "active":
                return JsonResponse(
                    {"error": "This account is inactive. Please contact the admin."},
                    status=403,
                )

            # Check the password
            if check_password(password, student_user["password"]):
                # Clear failed attempts after successful login
                failed_login_attempts.pop(email, None)

                # Update last login timestamp
                student_collection.update_one(
                    {"email": email}, {"$set": {"last_login": datetime.utcnow()}}
                )

                # Generate JWT token
                student_id = student_user.get("_id")
                tokens = generate_tokens(student_id)
                return JsonResponse(
                    {"username": student_user["name"], "token": tokens}, status=200
                )
            else:
                # Track failed attempts
                update_failed_attempts(email)
                return JsonResponse({"error": "Invalid email or password."}, status=401)

        except Exception as e:
            return JsonResponse({"error": "Invalid email or password."}, status=400)
    else:
        return JsonResponse({"error": "Invalid request method"}, status=400)

    
@api_view(["POST"])
@permission_classes([AllowAny])
def student_google_login(request):
     """
     Login view for students using Google OAuth
     Only matches existing accounts, no registration
     """
     try:
         data = request.data
         token = data.get("token")  # Google ID token
 
         if not token:
             return Response({"error": "Google token is required"}, status=400)
 
         # Verify the Google token
         try:
             # Use Google's library to validate the token with client ID from settings
            client_id = os.environ.get('GOOGLE_OAUTH2_CLIENT_ID') or settings.GOOGLE_OAUTH2_CLIENT_ID
            if not client_id:
                logger.error("Google OAuth client ID not configured")
                return Response({"error": "Google authentication not properly configured"}, status=500)
                 
            idinfo = id_token.verify_oauth2_token(
                token, google_requests.Request(), client_id)
 
            # Get user email from the token
            email = idinfo['email']
             
            # Check if email is verified by Google
            if not idinfo.get('email_verified', False):
                return Response({"error": "Email not verified by Google"}, status=400)
 
            # Check if student exists in database
            student_user = student_collection.find_one({"email": email})
             
            if not student_user:
                # No account found with this email
                return Response({
                    "error": "No account found with this Google email. Please login with username and password or contact administrator.",
                }, status=404)
            
            # Check if the account is active
            if student_user.get("status") != "active":
                return JsonResponse({"error": "This account is inactive. Please contact the admin."}, status=403)
 
            # Generate tokens
            tokens = generate_tokens(
                (student_user["_id"])
            )
 
            # Create response and set secure cookie
            response = {
                "username": student_user["name"],
                "token": tokens,
            }
             
            return JsonResponse(response, status=200, safe=False)  
 
         except ValueError as e:
             logger.error(f"Invalid Google token: {e}")
             return Response({"error": "Invalid Google token"}, status=401)
 
     except Exception as e:
         logger.error(f"Google login error: {e}")
         return Response({"error": "An unexpected error occurred"}, status=500)

def generate_reset_token(length=6):
    """
    Generates a random numeric reset token.

    Parameters:
    length (int): The length of the generated token (default is 6).

    Returns:
    str: A string containing a randomly generated numeric token.
    """
    return ''.join(random.choices(string.digits, k=length))


@api_view(["POST"])
@permission_classes([AllowAny])
def student_forgot_password(request):
    """
    Handle student password reset requests.

    This endpoint generates a password reset token and emails it to the user.

    Parameters:
    - request (HttpRequest): The request containing the student's email in JSON format.

    Returns:
    - JsonResponse: 
        - 200: If the reset token is successfully generated and sent via email.
        - 400: If the email is not found in the database.
        - 500: If an internal server error occurs.
    """
    try:
        email = request.data.get('email')
        response, status_code = request_password_reset(email)
        return JsonResponse(response, status=status_code)
    except Exception as e:
        return JsonResponse({"error": str(e)}, status=500)

@csrf_exempt
@handle_exceptions  # Apply the error handler   
def student_verify_One_Time_Password(request):
    """
    Verify the One-Time Password (OTP) for password reset.

    This endpoint checks if the provided OTP (reset token) matches the one stored in the database.

    Parameters:
    - request (HttpRequest): The request containing the student's email and OTP in JSON format.

    Returns:
    - JsonResponse: 
        - 200: If the OTP verification is successful.
        - 403: If the provided OTP is invalid.
        - 404: If no account is found for the given email.
        - 400: If an invalid request is sent.
    """
    if request.method == "POST":
        try:
            data = json.loads(request.body)
            email = data.get("email")
            token = data.get("token")
            response, status_code = verify_reset_token(email, token)
            return JsonResponse(response, status=status_code)
        except Exception as e:
            return JsonResponse({"error": str(e)}, status=400)
    return JsonResponse({"error": "Invalid request method"}, status=400)

@csrf_exempt
@handle_exceptions  # Apply the error handler
def student_reset_password(request):
    """
    Reset a student's password.

    This endpoint updates the student's password in the database after validating the request.

    Parameters:
    - request (HttpRequest): The request containing the student's email and new password in JSON format.

    Returns:
    - JsonResponse: 
        - 200: If the password is successfully updated.
        - 404: If the email is not found in the database.
        - 500: If there is an issue hashing the password or updating it in MongoDB.
        - 405: If the request method is not POST.
    """
    if request.method == "POST":
        try:
            data = json.loads(request.body)
            email = data.get("email")
            new_password = data.get("newPassword")
            reset_token = data.get('token')
            response, status_code = reset_student_password(email, new_password,reset_token)
            return JsonResponse(response, status=status_code)
        except Exception as e:
            return JsonResponse({"error": str(e)}, status=500)
    return JsonResponse({"error": "Invalid request method"}, status=405)

@csrf_exempt
@handle_exceptions  # Apply the error handler
def get_students(request):
    """
    Retrieve all student records.

    Fetches students from the database while excluding passwords.

    Parameters:
    request (HttpRequest): The request to fetch student data.

    Returns:
    JsonResponse: List of students or error message.
    """
    if request.method == 'GET':
        try:
            students = student_collection.find()
            student_list = []
            for student in students:
                student['_id'] = str(student['_id'])  # Convert ObjectId to string
                del student['password']  # Don't expose passwords
                student_list.append(student)

            return JsonResponse({'students': student_list}, status=200)
        except Exception as e:
            return JsonResponse({'error': str(e)}, status=500)
    else:
        return JsonResponse({'error': 'Invalid request method'}, status=400)

@csrf_exempt
@handle_exceptions  # Apply the error handler
def update_student(request, student_id):
    """
    Update a student's profile information.

    Parameters:
        request (HttpRequest): The HTTP request object containing JSON data.
        student_id (str): The unique identifier of the student.

    Expected JSON Payload:
        {
            "name": "Updated Name",
            "department": "Updated Department",
            "year": "Updated Year",
            "college_name": "Updated College Name",
            "status": "Active",
            "role": "admin"  # Role sent in the payload
        }

    Returns:
        JsonResponse:
            - 200: {"message": "Student details updated successfully"}
            - 400: {"error": "No valid fields provided for update"}
            - 403: {"error": "Permission denied"}
            - 404: {"error": "Student not found"}
            - 500: {"error": "Internal server error"}
    """
    if request.method == 'PUT':
        try:
            # Validate ObjectId
            if not ObjectId.is_valid(student_id):
                return JsonResponse({'error': 'Invalid student ID format'}, status=400)

            data = json.loads(request.body)
            role = data.get('role')
            if role not in ["admin", "superadmin"]:
                return JsonResponse({'error': 'Permission denied'}, status=403)

            student = student_collection.find_one({'_id': ObjectId(student_id)})

            if not student:
                return JsonResponse({'error': 'Student not found'}, status=404)

            # Allowed fields for update
            allowed_fields = ['name', 'department', 'year', 'college_name', 'status']

            # Sanitize and validate input fields
            update_data = {}
            for field in allowed_fields:
                if field in data:
                    update_data[field] = bleach.clean(data[field].strip())

            if update_data:
                student_collection.update_one({'_id': ObjectId(student_id)}, {'$set': update_data})
                return JsonResponse({'message': 'Student details updated successfully'}, status=200)
            else:
                return JsonResponse({'error': 'No valid fields provided for update'}, status=400)

        except json.JSONDecodeError:
            return JsonResponse({'error': 'Invalid JSON format'}, status=400)
        except Exception as e:
            return JsonResponse({'error': str(e)}, status=500)
    else:
        return JsonResponse({'error': 'Invalid request method'}, status=400)



from bson import ObjectId
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt

@csrf_exempt
@handle_exceptions  # Apply the error handler
def delete_student(request, student_id):
    """
    Delete a student record.

    Parameters:
        request (HttpRequest): The HTTP DELETE request.
        student_id (str): The unique identifier of the student to be deleted.

    Expected JSON Payload:
        {
            "role": "admin"  # Role sent in the payload
        }

    Returns:
        JsonResponse:
            - 200: {"message": "Student deleted successfully"}
            - 403: {"error": "Permission denied"}
            - 404: {"error": "Student not found"}
            - 500: {"error": "Internal server error"}
    """
    if request.method == 'DELETE':
        try:
            # data = json.loads(request.body)
            # role = data.get('role')
            # if role not in ["admin", "superadmin"]:
            #     return JsonResponse({'error': 'Permission denied'}, status=403)

            student = student_collection.find_one({'_id': ObjectId(student_id)})
            if not student:
                return JsonResponse({'error': 'Student not found'}, status=404)

            # Delete student from MongoDB
            student_collection.delete_one({'_id': ObjectId(student_id)})

            return JsonResponse({'message': 'Student deleted successfully'}, status=200)
        except Exception as e:
            return JsonResponse({'error': str(e)}, status=500)
    else:
        return JsonResponse({'error': 'Invalid request method'}, status=400)



# ===============================================================Profile=======================================================================

@csrf_exempt
@handle_exceptions  # Apply the error handler
def get_profile(request, userId):
    """
    Retrieve a student's profile.

    Parameters:
        request (HttpRequest): The HTTP GET request.
        userId (str): The unique identifier of the student.

    Returns:
        JsonResponse:
            - 200: {"message": "User found", "data": {...student details...}}
            - 400: {"error": "User not found"}
            - 500: {"error": "Internal server error"}
    """
    if request.method == "GET":
        try:
            # Find the student user by ID
            user = student_collection.find_one({"_id": ObjectId(userId)})

            if not user:
                return JsonResponse({"error": "User with this ID does not exist"}, status=400)

            # Ensure profile_image field is correctly retrieved as a filename
            profile_image = user.get("profile_image", "default.png")  # Default image if none

            # Prepare response data
            data = {
                "name": user.get("name"),
                "email": user.get("email"),
                "department": user.get("department", "N/A"),
                "year": user.get("year", "N/A"),
                "college_name": user.get("college_name", "N/A"),
                "status": user.get("status", "N/A"),
                "last_login": str(user.get("last_login")) if user.get("last_login") else "Never",
                "created_at": str(user.get("created_at")) if user.get("created_at") else "N/A",
                "saved_jobs": user.get("saved_jobs", []),
                "role": "student",
                "profile_image": profile_image,  # Send only filename, not binary data
            }

            return JsonResponse({"message": "Student user found", "data": data}, status=200)

        except Exception as e:
            return JsonResponse({"error": str(e)}, status=400)
    else:
        return JsonResponse({"error": "Invalid request method"}, status=400)

@csrf_exempt
@handle_exceptions  # Apply the error handler
def update_profile(request, userId):
    """
    Securely update a student's profile.

    Parameters:
        request (HttpRequest): The HTTP PUT request containing JSON data.
        userId (str): The unique identifier of the student.

    Returns:
        JsonResponse: Success or error message.
    """
    if request.method == "PUT":
        try:
            # Validate ObjectId
            if not ObjectId.is_valid(userId):
                return JsonResponse({"error": "Invalid user ID format"}, status=400)

            # Parse JSON request body
            data = json.loads(request.body)

            # Find the student user by ID
            user = student_collection.find_one({"_id": ObjectId(userId)})
            if not user:
                return JsonResponse({"error": "User not found"}, status=404)

            # Prevent modification of email
            data.pop("email", None)

            # Sanitize and validate input
            updated_fields = {}
            if "name" in data:
                updated_fields["name"] = bleach.clean(data["name"].strip())

            if updated_fields:
                student_collection.update_one({"_id": ObjectId(userId)}, {"$set": updated_fields})

            return JsonResponse({"message": "Profile updated successfully"}, status=200)

        except json.JSONDecodeError:
            return JsonResponse({"error": "Invalid JSON format"}, status=400)
        except Exception as e:
            return JsonResponse({"error": str(e)}, status=500)
    else:
        return JsonResponse({"error": "Invalid request method"}, status=400)

@csrf_exempt
@handle_exceptions  # Apply the error handler
def update_superadmin_profile(request, userId):
    """
    Securely update the super admin's profile.

    Parameters:
        request (HttpRequest): The HTTP PUT request containing JSON data.
        userId (str): The unique identifier of the super admin.

    Returns:
        JsonResponse: Success or error message.
    """
    if request.method == "PUT":
        try:
            # Validate ObjectId
            if not ObjectId.is_valid(userId):
                return JsonResponse({"error": "Invalid user ID format"}, status=400)

            # Parse JSON request body
            data = json.loads(request.body)

            # Find the super admin user by ID
            super_admin = superadmin_collection.find_one({"_id": ObjectId(userId)})
            if not super_admin:
                return JsonResponse({"error": "SuperAdmin not found"}, status=404)

            # Prevent modification of email
            data.pop("email", None)

            # Validate request payload
            if "name" not in data:
                return JsonResponse({"error": "Missing required fields"}, status=400)

            # Sanitize and validate input
            updated_fields = {
                "name": bleach.clean(data["name"].strip())
            }

            superadmin_collection.update_one({"_id": ObjectId(userId)}, {"$set": updated_fields})

            return JsonResponse({"message": "SuperAdmin profile updated successfully"}, status=200)

        except json.JSONDecodeError:
            return JsonResponse({"error": "Invalid JSON format"}, status=400)
        except Exception as e:
            return JsonResponse({"error": str(e)}, status=500)
    else:
        return JsonResponse({"error": "Invalid request method"}, status=400)



# ================================================================Jobs================================================================================================
@csrf_exempt
@handle_exceptions  # Apply the error handler
def save_job(request, pk):
    """
    Save a job to a student's saved jobs list.

    Parameters:
        request (HttpRequest): The HTTP POST request containing JSON data.
        pk (str): The unique identifier of the job.

    Expected JSON Payload:
        {
            "userId": "user_id_here"
        }

    Returns:
        JsonResponse:
            - 200: {"message": "Job saved successfully"}
            - 400: {"error": "User ID is required"} or {"error": "Invalid request method"}
            - 500: {"error": "Internal server error"}
    """
    if request.method == "POST":
        try:
            data = json.loads(request.body)
            user_id = data.get("userId")
            if not user_id:
                return JsonResponse(
                    {"error": "User ID is required"}, status=status.HTTP_400_BAD_REQUEST
                )

            student_collection.update_one(
                {"_id": ObjectId(user_id)},
                {"$addToSet": {"saved_jobs": pk}},
            )

            return JsonResponse({"message": "Job saved successfully"})
        except Exception as e:
            return JsonResponse({"error": str(e)}, status=status.HTTP_400_BAD_REQUEST)


@csrf_exempt
@handle_exceptions  # Apply the error handler
def unsave_job(request, pk):
    """
    Remove a job from a student's saved jobs list.

    Parameters:
        request (HttpRequest): The HTTP POST request containing JSON data.
        pk (str): The unique identifier of the job.

    Expected JSON Payload:
        {
            "userId": "user_id_here"
        }

    Returns:
        JsonResponse:
            - 200: {"message": "Job removed from saved"}
            - 400: {"error": "User ID is required"} or {"error": "Invalid request method"}
            - 500: {"error": "Internal server error"}
    """
    if request.method == "POST":
        try:
            data = json.loads(request.body)
            user_id = data.get("userId")

            if not user_id:
                return JsonResponse(
                    {"error": "User ID is required"}, status=status.HTTP_400_BAD_REQUEST
                )

            student_collection.update_one(
                {"_id": ObjectId(user_id)}, {"$pull": {"saved_jobs": pk}}
            )

            return JsonResponse({"message": "Job removed from saved"})
        except Exception as e:
            return JsonResponse({"error": str(e)}, status=status.HTTP_400_BAD_REQUEST)

@csrf_exempt
@handle_exceptions  # Apply the error handler
def get_saved_jobs(request, user_id):
    """
    Retrieve a student's list of saved jobs.

    Parameters:
        request (HttpRequest): The HTTP GET request.
        user_id (str): The unique identifier of the student.

    Returns:
        JsonResponse:
            - 200: {"message": "Saved jobs retrieved successfully", "jobs": [...list of jobs...] }
            - 400: {"error": "Invalid or missing user_id"} or {"error": "Invalid request method"}
            - 404: {"error": "User not found"}
            - 500: {"error": "Internal server error"}
    """
    try:
        if not user_id or not ObjectId.is_valid(user_id):
            return JsonResponse(
                {"error": "Invalid or missing user_id"}, status=status.HTTP_400_BAD_REQUEST
            )

        user = student_collection.find_one({"_id": ObjectId(user_id)})
        if not user:
            return JsonResponse(
                {"error": "User not found"}, status=status.HTTP_404_NOT_FOUND
            )

        saved_jobs = user.get("saved_jobs", [])

        jobs = []
        for job_id in saved_jobs:
            if not ObjectId.is_valid(job_id):
                continue  # Skip invalid ObjectIds

            job = job_collection.find_one({"_id": ObjectId(job_id)})
            if job:
                job["_id"] = str(job["_id"])
                jobs.append(job)

        return JsonResponse({"message": "Saved jobs retrieved successfully", "jobs": jobs})

    except Exception as e:
        return JsonResponse({"error": str(e)}, status=status.HTTP_400_BAD_REQUEST)


# ============================================================================ Internships =============================================================================================
@csrf_exempt
@handle_exceptions  # Apply the error handler
def save_internship(request, pk):
    """
    Save an internship to a student's saved internships list.

    Parameters:
        request (HttpRequest): The HTTP POST request containing JSON data.
        pk (str): The unique identifier of the internship.

    Expected JSON Payload:
        {
            "userId": "user_id_here"
        }

    Returns:
        JsonResponse:
            - 200: {"message": "Internship saved successfully"}
            - 400: {"error": "User ID is required"} or {"error": "Invalid request method"}
            - 500: {"error": "Internal server error"}
    """
    if request.method == "POST":
        try:
            data = json.loads(request.body)
            user_id = data.get("userId")
            if not user_id:
                return JsonResponse(
                    {"error": "User ID is required"}, status=status.HTTP_400_BAD_REQUEST
                )

            student_collection.update_one(
                {"_id": ObjectId(user_id)},
                {"$addToSet": {"saved_internships": pk}},
            )

            return JsonResponse({"message": "Internship saved successfully"})
        except Exception as e:
            return JsonResponse({"error": str(e)}, status=status.HTTP_400_BAD_REQUEST)

@csrf_exempt
@handle_exceptions  # Apply the error handler
def unsave_internship(request, pk):
    """
    Remove an internship from a student's saved internships list.

    Parameters:
        request (HttpRequest): The HTTP POST request containing JSON data.
        pk (str): The unique identifier of the internship.

    Expected JSON Payload:
        {
            "userId": "user_id_here"
        }

    Returns:
        JsonResponse:
            - 200: {"message": "Internship removed from saved"}
            - 400: {"error": "User ID is required"} or {"error": "Invalid request method"}
            - 500: {"error": "Internal server error"}
    """
    if request.method == "POST":
        try:
            data = json.loads(request.body)
            user_id = data.get("userId")

            if not user_id:
                return JsonResponse(
                    {"error": "User ID is required"}, status=status.HTTP_400_BAD_REQUEST
                )

            student_collection.update_one(
                {"_id": ObjectId(user_id)}, {"$pull": {"saved_internships": pk}}
            )

            return JsonResponse({"message": "Internship removed from saved"})
        except Exception as e:
            return JsonResponse({"error": str(e)}, status=status.HTTP_400_BAD_REQUEST)

@csrf_exempt
@handle_exceptions  # Apply the error handler
def get_saved_internships(request, user_id):
    """
    Retrieve a student's list of saved internships.

    Parameters:
        request (HttpRequest): The HTTP GET request.
        user_id (str): The unique identifier of the student.

    Returns:
        JsonResponse:
            - 200: {"message": "Saved internships retrieved successfully", "internships": [...list of internships...] }
            - 400: {"error": "Invalid or missing user_id"} or {"error": "Invalid request method"}
            - 404: {"error": "User not found"}
            - 500: {"error": "Internal server error"}
    """
    try:
        user = student_collection.find_one({"_id": ObjectId(user_id)})
        if not user:
            return JsonResponse(
                {"error": "User not found"}, status=status.HTTP_404_NOT_FOUND
            )

        saved_internships = user.get("saved_internships", [])
        internships = []

        for internship_id in saved_internships:
            internship = internship_collection.find_one({"_id": ObjectId(internship_id)})
            if internship:
                internship["_id"] = str(internship["_id"])
                internships.append(internship)
        
        return JsonResponse({"message": "Saved internships retrieved successfully", "internships": internships})
        
    except Exception as e:
        return JsonResponse({"error": str(e)}, status=status.HTTP_400_BAD_REQUEST)

# =========================================================================== ACHIEVEMENTS =============================================================================================

@csrf_exempt
@handle_exceptions  # Apply the error handler
@api_view(['POST'])
def post_student_achievement(request):
    """
    Handles submission of student achievements with file uploads.

    Expected JSON Payload:
    - name (str): Student name
    - achievement_description (str): Description of the achievement
    - achievement_type (str): Type of achievement (e.g., competition, certification)
    - company_name (str): Company/Organization name
    - date_of_achievement (str): Date of achievement
    - batch (str): Student batch
    - photo (file, optional): Uploaded photo

    Returns:
    - 201: Success message
    - 400: Missing required fields
    - 401: Unauthorized (invalid/missing token)
    - 500: Internal server error
    """
    # Extract and validate the Authorization header
    auth_header = request.headers.get('Authorization')
    if not auth_header or not auth_header.startswith("Bearer "):
        return JsonResponse({"error": "No token provided"}, status=401)

    token = auth_header.split(" ")[1]

    try:
        # Decode the JWT token
        payload = jwt.decode(
            token,
            settings.JWT_SECRET,
            algorithms=[settings.JWT_ALGORITHM],
            leeway=timedelta(seconds=300)  # Allow 5 minutes of clock skew
        )
        student_id = payload.get('student_user')
        if not student_id:
            return JsonResponse({"error": "Invalid token"}, status=401)

        # Handle form data (multipart/form-data)
        name = request.POST.get("name")
        achievement_description = request.POST.get("achievement_description")
        achievement_type = request.POST.get("achievement_type")
        company_name = request.POST.get("company_name")
        date_of_achievement = request.POST.get("date_of_achievement")
        batch = request.POST.get("batch")

        # Validate required fields
        required_fields = [
            "name", "achievement_description", "achievement_type",
            "company_name", "date_of_achievement", "batch"
        ]
        for field in required_fields:
            if not locals().get(field):
                return JsonResponse(
                    {"error": f"{field.replace('_', ' ').capitalize()} is required."},
                    status=400
                )

        # Handle file upload
        file_base64 = None
        if "photo" in request.FILES:
            photo = request.FILES["photo"]
            file_base64 = base64.b64encode(photo.read()).decode("utf-8")

        # Prepare the document for MongoDB
        achievement_data = {
            "student_id": student_id,
            "name": name,
            "achievement_description": achievement_description,
            "achievement_type": achievement_type,
            "company_name": company_name,
            "date_of_achievement": date_of_achievement,
            "batch": batch,
            "photo": file_base64,  # Base64-encoded file (optional)
            "is_approved": False,  # Pending approval by default
            "submitted_at": datetime.utcnow(),
        }

        # Insert the document into MongoDB
        achievement_collection.insert_one(achievement_data)

        return JsonResponse(
            {"message": "Achievement submitted successfully. Admin will contact you soon"},
            status=201
        )

    except jwt.ExpiredSignatureError:
        return JsonResponse({"error": "Token expired"}, status=401)
    except jwt.DecodeError:
        return JsonResponse({"error": "Invalid token"}, status=401)
    except Exception as e:
        # Log unexpected errors for debugging
        traceback.print_exc()
        return JsonResponse({"error": f"Server error: {str(e)}"}, status=500)

@csrf_exempt
@handle_exceptions  # Apply the error handler
def review_achievement(request, achievement_id):
    """
    Approve or reject a student achievement.

    Expected JSON Payload:
    - action (str): "approve" or "reject"

    Returns:
    - 200: Success message
    - 400: Invalid action or request
    - 404: Achievement not found
    - 500: Internal server error
    """
    if request.method == "POST":
        try:
            data = json.loads(request.body)
            action = data.get("action")
            if action not in ["approve", "reject"]:
                return JsonResponse({"error": "Invalid action"}, status=400)

            achievement = achievement_collection.find_one({"_id": ObjectId(achievement_id)})
            if not achievement:
                return JsonResponse({"error": "Achievement not found"}, status=404)

            is_publish = True if action == "approve" else False
            achievement_collection.update_one(
                {"_id": ObjectId(achievement_id)},
                {"$set": {"is_publish": is_publish, "updated_at": datetime.now()}}
            )

            message = "Achievement approved and published successfully" if is_publish else "Achievement rejected successfully"
            return JsonResponse({"message": message}, status=200)

        except Exception as e:
            return JsonResponse({"error": str(e)}, status=400)
    return JsonResponse({"error": "Invalid request method"}, status=400)

@csrf_exempt
@handle_exceptions  # Apply the error handler
def get_all_study_material(request):
    """
    Retrieve all available study materials.

    Returns:
    - 200: List of study materials
    - 404: No study materials found
    - 500: Internal server error
    """
    try:
        study_materials = study_material_collection.find({})
        study_material_list = []
        for material in study_materials:
            material["_id"] = str(material["_id"])  # Convert ObjectId to string
            study_material_list.append(material)

        if not study_material_list:
            return JsonResponse({"error": "Study materials not found"}, status=404)

        return JsonResponse({"study_materials": study_material_list}, status=200)

    except Exception as e:
        return JsonResponse({"error": str(e)}, status=500)


@csrf_exempt
@handle_exceptions  # Apply the error handler
def job_click(request):
    """
    Increment job click count when a job is viewed.

    Expected JSON Payload:
    - job_id (str): ID of the job clicked

    Returns:
    - 200: Success message
    - 400: Invalid job ID or request
    - 404: Job not found
    - 500: Internal server error
    """
    if request.method == "POST":
        try:
            data = json.loads(request.body)
            job_id = data.get("job_id")
            job = job_collection.find_one({"_id": ObjectId(job_id)})
            if not job:
                return JsonResponse({"error": "Job not found"}, status=404)

            job_collection.update_one(
                {"_id": ObjectId(job_id)},
                {"$inc": {"clicks": 1}}
            )

            return JsonResponse({"message": "Job click recorded successfully"}, status=200)

        except Exception as e:
            return JsonResponse({"error": str(e)}, status=400)


# ================================================================Applied Jobs================================================================================================


@csrf_exempt
@handle_exceptions  # Apply the error handler
def apply_job(request):
    """
    Handles job application submission for students.

    This function:
    - Extracts student ID and job ID from the request body.
    - Validates if both IDs are provided.
    - Checks if the student exists in the database.
    - Ensures the student has not already applied for the job.
    - Updates the student's applied job list with a pending confirmation status.

    Args:
        request (HttpRequest): The HTTP request containing studentId and jobId in JSON format.

    Returns:
        JsonResponse: A response indicating success or failure of the job application.
    """
    try:
        data = json.loads(request.body)
        student_id = data.get("studentId")
        job_id = data.get("jobId")

        if not student_id or not job_id:
            return JsonResponse({"error": "Student ID and Job ID are required"}, status=400)

        # Retrieve the student document
        student = student_collection.find_one({"_id": ObjectId(student_id)})
        if not student:
            return JsonResponse({"error": "Student not found"}, status=404)

        applied_jobs = student.get("applied_jobs", [])
        if any(job["job_id"] == str(ObjectId(job_id)) for job in applied_jobs):
            return JsonResponse({"message": "Job already applied"}, status=200)

        # Update the student's applied jobs in the database with confirmation status as null
        result = student_collection.update_one(
            {"_id": ObjectId(student_id)},
            {"$addToSet": {"applied_jobs": {
                "job_id": str(ObjectId(job_id)),  # Convert ObjectId to string
                "confirmed": None  # Set confirmed status to null
            }}}
        )

        if result.modified_count == 0:
            return JsonResponse({"error": "Failed to update applied jobs"}, status=400)

        return JsonResponse({"message": "Job application recorded successfully"})

    except Exception as e:
        return JsonResponse({"error": str(e)}, status=400)

@csrf_exempt
@handle_exceptions  # Apply the error handler
def confirm_job(request):
    """
    Updates the confirmation status of a job application.

    This function:
    - Extracts student ID, job ID, and confirmation status from the request body.
    - Validates required fields.
    - Updates the student's applied jobs with the provided confirmation status.
    - Updates the job document by adding the student ID to the applied list.

    Args:
        request (HttpRequest): The HTTP request containing studentId, jobId, and confirmed status in JSON format.

    Returns:
        JsonResponse: A response indicating whether the confirmation status was updated successfully or not.
    """
    try:
        data = json.loads(request.body)
        student_id = data.get("studentId")
        job_id = data.get("jobId")
        confirmed = data.get("confirmed")

        if not student_id or not job_id or confirmed is None:
            return JsonResponse({"error": "Student ID, Job ID, and confirmation status are required"}, status=400)

        # Update the confirmation status of the applied job in the student collection
        result = student_collection.update_one(
            {"_id": ObjectId(student_id), "applied_jobs.job_id": job_id},
            {"$set": {"applied_jobs.$.confirmed": confirmed}}
        )

        if result.modified_count == 0:
            return JsonResponse({"error": "Failed to update confirmation status. No matching document found."}, status=400)

        # Update the job collection to add the student ID to the applied array
        job_result = job_collection.update_one(
            {"_id": ObjectId(job_id)},
            {"$addToSet": {"applied": str(ObjectId(student_id))}}  # Use $addToSet to avoid duplicates
        )


        if job_result.modified_count == 0:
            return JsonResponse({"error": "Failed to update job data. No matching document found."}, status=400)

        return JsonResponse({"message": "Job application status updated successfully"})
    except Exception as e:
        return JsonResponse({"error": str(e)}, status=400)
logger = logging.getLogger(__name__)

@csrf_exempt
@handle_exceptions  # Apply the error handler
def get_applied_jobs(request, userId):
    """
    Retrieves all jobs applied by a specific student.

    This function:
    - Fetches the student document using the provided user ID.
    - Extracts the list of applied jobs.
    - Returns the applied jobs list in JSON format.

    Args:
        request (HttpRequest): The HTTP request to fetch applied jobs.
        userId (str): The ID of the student.

    Returns:
        JsonResponse: A response containing the list of applied jobs or an error message if the student is not found.
    """
    try:
        # Validate the user ID
        if not userId or not ObjectId.is_valid(userId):
            return JsonResponse({"error": "Invalid or missing userId"}, status=400)

        # Find the student by ID
        student = student_collection.find_one({"_id": ObjectId(userId)})

        if not student:
            return JsonResponse({"error": "Student not found"}, status=404)

        # Get the list of applied job IDs
        applied_jobs = student.get("applied_jobs", [])

        # Fetch job data for each job ID
        jobs = []
        for job_id in applied_jobs:
            if not ObjectId.is_valid(job_id.get("job_id")):
                continue  # Skip invalid ObjectIds

            job = job_collection.find_one({"_id": ObjectId(job_id.get("job_id"))})
            if job:
                job["_id"] = str(job["_id"])
                jobs.append(job)

        return JsonResponse({"message": "Applied jobs retrieved successfully", "jobs": jobs})

    except Exception as e:
        logger.error(f"Error fetching applied jobs: {str(e)}")
        return JsonResponse({"error": str(e)}, status=400)


logger = logging.getLogger(__name__)

@csrf_exempt
@handle_exceptions  # Apply the error handler
def apply_internship(request):
    try:
        data = json.loads(request.body)
        student_id = data.get("studentId")
        internship_id = data.get("internshipId")

        if not student_id or not internship_id:
            return JsonResponse({"error": "Student ID and Internship ID are required"}, status=400)

        # Retrieve the student document
        student = student_collection.find_one({"_id": ObjectId(student_id)})
        if not student:
            return JsonResponse({"error": "Student not found"}, status=404)

        applied_internships = student.get("applied_internships", [])
        if any(internship["internship_id"] == str(ObjectId(internship_id)) for internship in applied_internships):
            return JsonResponse({"message": "Internship already applied"}, status=200)

        # Update the student's applied internships in the database with confirmation status as null
        result = student_collection.update_one(
            {"_id": ObjectId(student_id)},
            {"$addToSet": {"applied_internships": {
                "internship_id": str(ObjectId(internship_id)),  # Convert ObjectId to string
                "confirmed": None  # Set confirmed status to null
            }}}
        )

        if result.modified_count == 0:
            return JsonResponse({"error": "Failed to update applied internships"}, status=400)

        return JsonResponse({"message": "Internship application recorded successfully"})

    except Exception as e:
        return JsonResponse({"error": str(e)}, status=400)

@csrf_exempt
@handle_exceptions  # Apply the error handler
def confirm_internship(request):
    try:
        data = json.loads(request.body)
        student_id = data.get("studentId")
        internship_id = data.get("internshipId")
        confirmed = data.get("confirmed")

        if not student_id or not internship_id or confirmed is None:
            return JsonResponse({"error": "Student ID, Internship ID, and confirmation status are required"}, status=400)

        # Update the confirmation status of the applied internship in the student collection
        result = student_collection.update_one(
            {"_id": ObjectId(student_id), "applied_internships.internship_id": internship_id},
            {"$set": {"applied_internships.$.confirmed": confirmed}}
        )

        if result.modified_count == 0:
            return JsonResponse({"error": "Failed to update confirmation status. No matching document found."}, status=400)

        # Update the internship collection to add the student ID to the applied array
        internship_result = internship_collection.update_one(
            {"_id": ObjectId(internship_id)},
            {"$addToSet": {"applied": str(ObjectId(student_id))}}  # Use $addToSet to avoid duplicates
        )

        if internship_result.modified_count == 0:
            return JsonResponse({"error": "Failed to update internship data. No matching document found."}, status=400)

        return JsonResponse({"message": "Internship application status updated successfully"})
    except Exception as e:
        return JsonResponse({"error": str(e)}, status=400)

from bson import ObjectId
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
import logging

logger = logging.getLogger(__name__)

@csrf_exempt
@handle_exceptions  # Apply the error handler
def get_applied_internships(request, userId):
    try:
        # Validate the user ID
        if not userId or not ObjectId.is_valid(userId):
            return JsonResponse({"error": "Invalid or missing userId"}, status=400)

        # Find the student by ID
        student = student_collection.find_one({"_id": ObjectId(userId)})

        if not student:
            return JsonResponse({"error": "Student not found"}, status=404)

        # Get the list of applied internship IDs
        applied_internships = student.get("applied_internships", [])

        # Fetch internship data for each internship ID
        internships = []
        for internship_id in applied_internships:
            if not ObjectId.is_valid(internship_id.get("internship_id")):
                continue  # Skip invalid ObjectIds

            internship = internship_collection.find_one({"_id": ObjectId(internship_id.get("internship_id"))})
            if internship:
                internship["_id"] = str(internship["_id"])
                internships.append(internship)

        return JsonResponse({"message": "Applied internships retrieved successfully", "internships": internships})

    except Exception as e:
        logger.error(f"Error fetching applied internships: {str(e)}")
        return JsonResponse({"error": str(e)}, status=400)
