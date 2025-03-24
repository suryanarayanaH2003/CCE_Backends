import jwt
import json
from datetime import datetime, timedelta
from django.http import JsonResponse
from bson import ObjectId
from pymongo import MongoClient
from django.contrib.auth.hashers import make_password, check_password
from django.views.decorators.csrf import csrf_exempt
import re
import os
from django.core.mail import send_mail
from django.conf import settings
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
import random
import string
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import logging
from rest_framework.exceptions import AuthenticationFailed
import base64
from bson.errors import InvalidId
import pytesseract
import cv2
import numpy as np
import google.generativeai as genai
from PIL import Image, ImageEnhance, ImageFilter
from django.utils import timezone
from google.oauth2 import id_token
from google.auth.transport import requests as google_requests
from rest_framework.response import Response
from rest_framework import status
from django.http import JsonResponse
import logging
from django.utils import timezone
import pytz
from datetime import datetime
from .internship_views import *
from .job_views import *
from .achievement_views import *
from .study_material_views import *



from dotenv import load_dotenv

load_dotenv()

# Configuration
JWT_SECRET = os.environ.get("JWT_SECRET", "secret")
JWT_ALGORITHM = "HS256"
DATABASE_URL = os.environ.get(
    "DATABASE_URL", 'mongodb+srv://ihub:ihub@cce.ksniz.mongodb.net/')
DATABASE_NAME = "CCE"
ADMIN_COLLECTION_NAME = "admin"
INTERNSHIP_COLLECTION_NAME = "internships"
JOB_COLLECTION_NAME = "jobs"
ACHIEVEMENT_COLLECTION_NAME = "achievement"
SUPERADMIN_COLLECTION_NAME = "superadmin"
STUDENT_COLLECTION_NAME = "students"
REVIEWS_COLLECTION_NAME = "reviews"
STUDY_MATERIAL_COLLECTION_NAME = "studyMaterial"
CONTACT_US_COLLECTION_NAME = "contact_us"
STUDENT_ACHIEVEMENT_COLLECTION_NAME = "student_achievement"
MESSAGE_COLLECTION_NAME = "message"
EXAM_COLLECTION_NAME = "exam"
DELETED_JOB_COLLECTION_NAME = 'deleted_job'
DELETED_INTERNSHIP_COLLECTION_NAME = 'deleted_internship'

# Logger setup
logger = logging.getLogger(__name__)

# MongoDB connection setup
client = MongoClient(DATABASE_URL)
db = client[DATABASE_NAME]
admin_collection = db[ADMIN_COLLECTION_NAME]
internship_collection = db[INTERNSHIP_COLLECTION_NAME]
job_collection = db[JOB_COLLECTION_NAME]
achievement_collection = db[ACHIEVEMENT_COLLECTION_NAME]
superadmin_collection = db[SUPERADMIN_COLLECTION_NAME]
student_collection = db[STUDENT_COLLECTION_NAME]
reviews_collection = db[REVIEWS_COLLECTION_NAME]
study_material_collection = db[STUDY_MATERIAL_COLLECTION_NAME]
contactus_collection = db[CONTACT_US_COLLECTION_NAME]
student_achievement_collection = db[STUDENT_ACHIEVEMENT_COLLECTION_NAME]
message_collection = db[MESSAGE_COLLECTION_NAME]
exam_collection = db[EXAM_COLLECTION_NAME]
deleted_job_collection = db[DELETED_JOB_COLLECTION_NAME]
deleted_internship_collection = db[DELETED_INTERNSHIP_COLLECTION_NAME]

# Security settings
FAILED_LOGIN_ATTEMPTS = {}
LOCKOUT_DURATION = timedelta(minutes=2)


def generate_tokens(admin_user):
    """Generates JWT tokens for admin authentication.

    Args:
        admin_user (str): The admin user ID.

    Returns:
        dict: A dictionary containing the JWT token.
    """
    payload = {
        'admin_user': str(admin_user),
        'role': 'admin',
        "exp": datetime.utcnow() + timedelta(days=1),
        "iat": datetime.utcnow(),
    }

    token = jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)
    return {'jwt': token}


def generate_tokens_superadmin(superadmin_user):
    """Generates JWT tokens for superadmin authentication.

    Args:
        superadmin_user (str): The superadmin user ID.

    Returns:
        dict: A dictionary containing the JWT token.
    """
    payload = {
        'superadmin_user': str(superadmin_user),
        'role': 'superadmin',
        "exp": datetime.utcnow() + timedelta(days=1),
        "iat": datetime.utcnow(),
    }

    token = jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)
    return {"jwt": token}


def is_strong_password(password):
    """Checks if a password meets complexity requirements.

    Args:
        password (str): The password to validate.

    Returns:
        tuple: (bool, str) - True if strong, False and error message otherwise.
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


def send_confirmation_email(to_email, name, password):
    """Sends a confirmation email to the newly created admin user.

    Args:
        to_email (str): The recipient's email address.
        name (str): The admin's name.
        password (str): The admin's password (for inclusion in the email).
    """
    subject = "Admin Account Created"
    body = f"""
    Your admin account has been successfully created on the CCE platform.
    Username: {name}
    Password: {password}
    Please keep your credentials safe and secure.
    """

    msg = MIMEMultipart()
    msg['From'] = settings.EMAIL_HOST_USER
    msg['To'] = to_email
    msg['Subject'] = subject

    msg.attach(MIMEText(body, 'plain'))

    try:
        # Connect to the Gmail SMTP server
        server = smtplib.SMTP(settings.EMAIL_HOST, settings.EMAIL_PORT)
        server.starttls()  # Secure the connection
        server.login(settings.EMAIL_HOST_USER, settings.EMAIL_HOST_PASSWORD)  # Login with credentials
        text = msg.as_string()
        server.sendmail(settings.EMAIL_HOST_USER, to_email, text)  # Send the email
        server.quit()  # Close the connection
        print(f"Confirmation email sent to {to_email}")
    except Exception as e:
        print(f"Error sending email: {str(e)}")


@csrf_exempt
def admin_signup(request):
    """Registers a new admin user.
 
    Args:
        request (HttpRequest): The HTTP request object.

    Returns:
        JsonResponse: A JSON response indicating success or failure.
    """
    if request.method == "POST":
        try:
            data = json.loads(request.body)
            name = data.get('name')
            email = data.get('email')
            password = data.get('password')
            department = data.get('department')
            college_name = data.get('college_name')
            mobile_number = data.get('mobile_number')

            if not all([name, email, password, department, college_name]):
                return JsonResponse(
                    {'error': 'All fields are required'}, status=400)

            if admin_collection.find_one({'email': email}):
                return JsonResponse(
                    {'error': 'Email already assigned to an admin'}, status=400)

            is_valid, error_message = is_strong_password(password)
            if not is_valid:
                return JsonResponse({'error': error_message}, status=400)

            if not mobile_number.isdigit() or len(mobile_number) != 10:
                return JsonResponse(
                    {'error': 'Enter a valid 10-digit mobile number'}, status=400)

            hashed_password = make_password(password)

            admin_user = {
                'name': name,
                'email': email,
                'password': hashed_password,
                'department': department,
                'college_name': college_name,
                'mobile_number': mobile_number,
                'status': 'Active',
                'created_at': datetime.now(),
                'last_login': None
            }

            admin_collection.insert_one(admin_user)
            send_confirmation_email(email, name, password)

            return JsonResponse(
                {'message': 'Admin user created, confirmation email sent.'},
                status=201)

        except Exception as e:
            return JsonResponse({'error': str(e)}, status=400)

    else:
        return JsonResponse({'error': 'Invalid request method'}, status=400)


def generate_reset_token(length=6):
    """Generates a numeric reset token of specified length.

    Args:
        length (int): The length of the reset token.

    Returns:
        str: A numeric reset token.
    """
    return ''.join(random.choices(string.digits, k=length))
 
@csrf_exempt
def admin_login(request):
    """Authenticates an admin user and generates a JWT token upon successful login.

    Args:
        request (HttpRequest): The HTTP request object containing email and password.

    Returns:
        JsonResponse: A JSON response with username and token on success, or an error message on failure.
    """
    if request.method == "POST":
        try:
            data = json.loads(request.body)
            email = data.get("email")
            password = data.get("password")

            if "@sns" not in email:
                return JsonResponse({'error': 'Email must contain domain id'}, status=400)

            if email in FAILED_LOGIN_ATTEMPTS:
                lockout_data = FAILED_LOGIN_ATTEMPTS[email]
                if lockout_data['count'] >= 3 and datetime.now() < lockout_data['lockout_until']:
                    return JsonResponse(
                        {'error': 'Too many failed attempts. Please try again after 2 minutes.'},
                        status=403)

            admin_user = admin_collection.find_one({'email': email})

            if not admin_user:
                return JsonResponse(
                    {'error': 'Account not found with this email id'}, status=404)

            if not admin_user.get('status', 'Active') == 'Active':
                return JsonResponse(
                    {'error': 'Admin account is deactivated. Please contact support.'},
                    status=403)

            if check_password(password, admin_user['password']):
                FAILED_LOGIN_ATTEMPTS.pop(email, None)

                admin_id = admin_user.get('_id')
                tokens = generate_tokens(admin_id)

                admin_collection.update_one(
                    {'email': email}, {'$set': {'last_login': datetime.now()}})

                response = JsonResponse(
                    {'username': admin_user['name'], 'tokens': tokens, 'last_login': datetime.now()},
                    status=200)

                return response
            else:
                if email not in FAILED_LOGIN_ATTEMPTS:
                    FAILED_LOGIN_ATTEMPTS[email] = {'count': 1, 'lockout_until': None}
                else:
                    FAILED_LOGIN_ATTEMPTS[email]['count'] += 1
                    if FAILED_LOGIN_ATTEMPTS[email]['count'] >= 3:
                        FAILED_LOGIN_ATTEMPTS[email]['lockout_until'] = datetime.now() + LOCKOUT_DURATION

                return JsonResponse({'error': 'Invalid email or password.'}, status=401)

        except Exception as e:
            return JsonResponse({"error": str(e)}, status=400)
    else:
        return JsonResponse({'error': 'Invalid request method'}, status=400)


@api_view(["POST"])
@permission_classes([AllowAny])
def admin_google_login(request):
    """Logs in an admin user using Google OAuth 2.0.

    Args:
        request (HttpRequest): The HTTP request object containing the Google ID token.

    Returns:
        Response: A DRF Response with username and token on success, or an error message on failure.
    """
    try:
        data = request.data
        token = data.get("token")  # Google ID token

        if not token:
            return Response({"error": "Google token is required"}, status=400)

        try:
            client_id = os.environ.get('GOOGLE_OAUTH2_CLIENT_ID') or settings.GOOGLE_OAUTH2_CLIENT_ID
            if not client_id:
                logger.error("Google OAuth client ID not configured")
                return Response({"error": "Google authentication not properly configured"}, status=500)

            idinfo = id_token.verify_oauth2_token(
                token, google_requests.Request(), client_id)

            email = idinfo['email']

            if not idinfo.get('email_verified', False):
                return Response({"error": "Email not verified by Google"}, status=400)

            admin_user = admin_collection.find_one({"email": email})

            if not admin_user:
                return Response({
                    "error": "No account found with this Google email. "
                             "Please login with username and password or contact administrator.",
                }, status=404)

            if not admin_user.get('status', 'Active') == 'Active':
                return JsonResponse(
                    {'error': 'Admin account is deactivated. Please contact support.'},
                    status=403)

            tokens = generate_tokens(
                (admin_user["_id"])
            )

            admin_collection.update_one({'email': email}, {'$set': {'last_login': datetime.now()}})

            response = {
                "username": admin_user["name"],
                "token": tokens,
                'last_login': datetime.now()
            }

            return JsonResponse(response, status=200, safe=False)

        except ValueError as e:
            logger.error(f"Invalid Google token: {e}")
            return Response({"error": "Invalid Google token"}, status=401)

    except Exception as e:
        logger.error(f"Google login error: {e}")
        return Response({"error": "An unexpected error occurred"}, status=500)


@api_view(["POST"])
@permission_classes([AllowAny])
def forgot_password(request):
    """Sends a password reset token to the user's email address.

    Args:
        request (HttpRequest): The HTTP request object containing the email address.

    Returns:
        Response: A DRF Response indicating success or failure.
    """
    try:
        email = request.data.get('email')
        user = admin_collection.find_one({"email": email})
        if not user:
            return Response({"error": "Email not found"}, status=400)

        reset_token = generate_reset_token()
        expiration_time = datetime.utcnow() + timedelta(hours=1)

        admin_collection.update_one(
            {"email": email},
            {"$set": {"password_reset_token": reset_token,
                      "password_reset_expires": expiration_time}}
        )

        send_mail(
            'Password Reset Request',
            f'Use this token to reset your password: {reset_token}',
            settings.DEFAULT_FROM_EMAIL,
            [email],
        )

        return Response({"message": "Password reset token sent to your email"}, status=200)
    except Exception as e:
        return Response({"error": str(e)}, status=500)


@api_view(["POST"])
@permission_classes([AllowAny])
def verify_otp(request):
    """Verifies the OTP (One-Time Password) entered by the user.

    Args:
        request (HttpRequest): The HTTP request object containing the email and OTP.

    Returns:
        Response: A DRF Response indicating success or failure.
    """
    try:
        email = request.data.get('email')
        otp = request.data.get('otp')

        user = admin_collection.find_one({"email": email})
        if not user:
            return Response({"error": "User not found"}, status=404)

        if user.get("password_reset_token") != otp:
            return Response({"error": "Invalid OTP"}, status=400)

        if user.get("password_reset_expires") < datetime.utcnow():
            return Response({"error": "OTP has expired"}, status=400)

        return Response({"message": "verification successfully"}, status=200)
    except Exception as e:
        return Response({"error": str(e)}, status=500)


@csrf_exempt
def reset_password(request):
    """Resets the user's password after verifying the OTP.

    Args:
        request (HttpRequest): The HTTP request object containing the email and new password.

    Returns:
        JsonResponse: A JSON response indicating success or failure.
    """
    if request.method == 'POST':
        try:
            data = json.loads(request.body)
            email = data.get('email')
            new_password = data.get('newPassword')

            if not email or not new_password:
                return JsonResponse(
                    {"error": "Email and new password are required."}, status=400)

            user = admin_collection.find_one({"email": email})
            if not user:
                return JsonResponse({"error": "User not found."}, status=404)

            hashed_password = make_password(new_password)

            if not hashed_password.startswith("pbkdf2_sha256$"):
                return JsonResponse(
                    {"error": "Failed to hash the password correctly."}, status=500)

            result = admin_collection.update_one(
                {"email": email},
                {"$set": {
                    "password": hashed_password,
                    "password_reset_token": None,
                    "password_reset_expires": None
                }}
            )

            if result.modified_count == 0:
                return JsonResponse(
                    {"error": "Failed to update the password in MongoDB."}, status=500)

            return JsonResponse({"message": "Password reset successfully"}, status=200)

        except Exception as e:
            return JsonResponse({"error": f"An error occurred: {str(e)}"}, status=500)

    return JsonResponse(
        {"error": "Invalid request method. Use POST."}, status=405)


@csrf_exempt
def get_admin_list(request):
    """Retrieves a list of all admin users.

    Args:
        request (HttpRequest): The HTTP request object.

    Returns:
        JsonResponse: A JSON response containing a list of admin users or an error message.
    """
    try:
        admins = admin_collection.find()
        admin_list = []

        for admin in admins:
            admin["_id"] = str(admin["_id"])
            admin_list.append(admin)

        return JsonResponse({"admins": admin_list}, status=200)

    except Exception as e:
        return JsonResponse({"error": str(e)}, status=500)


@csrf_exempt
def admin_details(request, id):
    """Retrieves detailed information for a specific admin, including associated jobs,
    internships, achievements, and exams.

    Args:
        request (HttpRequest): The HTTP request object.
        id (str): The ID of the admin user.

    Returns:
        JsonResponse: A JSON response containing admin details, jobs, internships, and achievements,
                      or an error message.
    """
    if request.method == 'GET':
        try:
            admin = admin_collection.find_one({'_id': ObjectId(id)})
            if not admin:
                return JsonResponse({'error': 'Admin not found'}, status=404)

            admin_data = _format_admin_details(admin)
            jobs_list = _fetch_and_format_jobs(id)
            internships_list = _fetch_and_format_internships(id)
            achievements_list = _fetch_and_format_achievements(id)
            exams_list = _fetch_and_format_exams(id)

            return JsonResponse({
                'admin': admin_data,
                'jobs': jobs_list,
                'internships': internships_list,
                'achievements': achievements_list,
                'exams': exams_list
            }, status=200)

        except Exception as e:
            logger.error("Error fetching admin details: %s", str(e))
            return JsonResponse({'error': f'An error occurred: {str(e)}'}, status=400)
    else:
        return JsonResponse({'error': 'Invalid request method'}, status=405)


def _format_admin_details(admin):
    """Formats admin details for the JSON response."""
    admin['_id'] = str(admin['_id'])
    last_login = admin.get('last_login')
    last_login = last_login.strftime('%Y-%m-%d %H:%M:%S') if last_login else "Never logged in"

    return {
        '_id': admin['_id'],
        'name': admin.get('name', 'N/A'),
        'email': admin.get('email', 'N/A'),
        'status': admin.get('status', 'Active'),
        'department': admin.get('department', 'N/A'),
        'college_name': admin.get('college_name', 'N/A'),
        'created_at': admin.get('created_at', datetime.now()).strftime('%Y-%m-%d %H:%M:%S'),
        'last_login': last_login
    }


def _fetch_and_format_jobs(admin_id):
    """Fetches and formats jobs posted by the admin."""
    jobs = job_collection.find({'admin_id': str(admin_id)})
    jobs_list = []
    for job in jobs:
        job['_id'] = str(job['_id'])
        job_data = job.get('job_data', {})
        job_data['_id'] = job['_id']
        job_data['updated_at'] = job.get('updated_at', "N/A")
        jobs_list.append(job_data)
    return jobs_list


def _fetch_and_format_internships(admin_id):
    """Fetches and formats internships posted by the admin."""
    internships = internship_collection.find({'admin_id': str(admin_id)})
    internships_list = []
    for internship in internships:
        internship['_id'] = str(internship['_id'])
        internship_data = internship.get('internship_data', {})
        internship_data['_id'] = internship['_id']
        internship_data['updated_at'] = internship.get('updated_at', "N/A")
        internships_list.append(internship_data)
    return internships_list


def _fetch_and_format_achievements(admin_id):
    """Fetches and formats achievements posted by the admin."""
    achievements = achievement_collection.find({'admin_id': str(admin_id)})
    achievements_list = []
    for achievement in achievements:
        achievement['_id'] = str(achievement['_id'])
        achievements_list.append(achievement)
    return achievements_list


def _fetch_and_format_exams(admin_id):
    """Fetches and formats exams posted by the admin."""
    exams = exam_collection.find({'admin_id': str(admin_id)})
    exams_list = []
    for exam in exams:
        exam['_id'] = str(exam['_id'])
        exam_data = exam.get('exam_data', {})
        exam_data['_id'] = exam['_id']
        exam_data['updated_at'] = exam.get('updated_at', "N/A")
        exams_list.append(exam_data)
    return exams_list


@csrf_exempt
def edit_admin_details(request, id):
    """Edits the details of a specific admin.

    Args:
        request (HttpRequest): The HTTP request object containing the updated admin details.
        id (str): The ID of the admin user to be updated.

    Returns:
        JsonResponse: A JSON response indicating success or failure.
    """
    if request.method == 'PUT':
        try:
            data = json.loads(request.body)
            admin = admin_collection.find_one({'_id': ObjectId(id)})
            if not admin:
                return JsonResponse({'error': 'Admin not found'}, status=404)

            # Update fields if provided in the request
            if 'name' in data:
                admin['name'] = data['name']
            if 'email' in data:
                admin['email'] = data['email']
            if 'status' in data:
                admin['status'] = data['status']
            if 'department' in data:
                admin['department'] = data['department']
            if 'college_name' in data:
                admin['college_name'] = data['college_name']

            # Save the updated admin details back to the database
            admin_collection.update_one({'_id': ObjectId(id)}, {'$set': admin})

            return JsonResponse({'success': 'Admin details updated successfully'}, status=200)

        except Exception as e:
            return JsonResponse({'error': f'An error occurred: {str(e)}'}, status=400)
    else:
        return JsonResponse({'error': 'Invalid request method'}, status=405)


@csrf_exempt
def admin_status_update(request, id):
    """Updates the status of a specific admin (Active/Inactive).

    Args:
        request (HttpRequest): The HTTP request object containing the new status.
        id (str): The ID of the admin user to be updated.

    Returns:
        JsonResponse: A JSON response indicating success or failure.
    """
    if request.method == 'POST':
        try:
            data = json.loads(request.body)
            new_status = data.get("status")
            print(new_status)

            if new_status not in ["Active", "Inactive"]:
                return JsonResponse({'error': 'Invalid status value'}, status=400)

            update_result = admin_collection.update_one(
                {'_id': ObjectId(id)}, {'$set': {'status': new_status}})

            if update_result.matched_count == 0:
                return JsonResponse({'error': 'Admin not found'}, status=404)

            return JsonResponse(
                {'message': f'Admin status updated to {new_status}'}, status=200)

        except Exception as e:
            return JsonResponse({'error': f'An error occurred: {str(e)}'}, status=400)
    else:
        return JsonResponse({'error': 'Invalid request method'}, status=405)


@csrf_exempt
def super_admin_signup(request):
    """Registers a new super admin user.

    Args:
        request (HttpRequest): The HTTP request object containing super admin details.

    Returns:
        JsonResponse: A JSON response indicating success or failure.
    """
    if request.method == "POST":
        try:
            data = json.loads(request.body)
            name = data.get("name")
            email = data.get("email")
            password = data.get("password")

            if "@sns" not in email:
                return JsonResponse(
                    {"error": "Email must contain domain id"}, status=400)

            if superadmin_collection.find_one({'email': email}):
                return JsonResponse(
                    {'error': 'Super admin user with this email already exists'},
                    status=400)

            if not re.match(
                r"^(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$",
                    password):
                return JsonResponse(
                    {
                        "error": "Password must be at least 8 characters long, "
                                 "contain an uppercase letter, a number, and a special character"
                    },
                    status=400,
                )

            password = make_password(password)

            super_admin_user = {
                'name': name,
                'email': email,
                'password': password,
            }

            superadmin_collection.insert_one(super_admin_user)

            return JsonResponse(
                {'message': 'Super admin user created successfully'}, status=200)
        except Exception as e:
            return JsonResponse({"error": str(e)}, status=400)
    else:
        return JsonResponse({"error": "Invalid request method"}, status=400)


@csrf_exempt
def super_admin_login(request):
    """Authenticates a super admin user and generates a JWT token.

    Args:
        request (HttpRequest): The HTTP request object containing email and password.

    Returns:
        JsonResponse: A JSON response with username and token on success, or an error message on failure.
    """
    if request.method == "POST":
        try:
            data = json.loads(request.body)
            email = data.get("email")
            password = data.get("password")

            if "@sns" not in email:
                return JsonResponse({'error': 'Email must contain domain id'}, status=400)

            if email in FAILED_LOGIN_ATTEMPTS:
                lockout_data = FAILED_LOGIN_ATTEMPTS[email]
                if lockout_data['count'] >= 3 and datetime.now() < lockout_data['lockout_until']:
                    return JsonResponse(
                        {'error': 'Too many failed attempts. Please try again after 2 minutes.'},
                        status=403)

            super_admin_user = superadmin_collection.find_one({'email': email})

            if not super_admin_user:
                return JsonResponse(
                    {'error': 'Account not found with this email id'}, status=404)

            if check_password(password, super_admin_user['password']):
                FAILED_LOGIN_ATTEMPTS.pop(email, None)

                super_admin_id = super_admin_user.get('_id')
                tokens = generate_tokens_superadmin(super_admin_id)

                superadmin_collection.update_one(
                    {'email': email}, {'$set': {'last_login': datetime.now()}})
                
                return JsonResponse(
                    {'username': super_admin_user['name'], 'tokens': tokens},
                    status=200)
            else:
                if email not in FAILED_LOGIN_ATTEMPTS:
                    FAILED_LOGIN_ATTEMPTS[email] = {'count': 1, 'lockout_until': None}
                else:
                    FAILED_LOGIN_ATTEMPTS[email]['count'] += 1
                    if FAILED_LOGIN_ATTEMPTS[email]['count'] >= 3:
                        FAILED_LOGIN_ATTEMPTS[email]['lockout_until'] = datetime.now() + LOCKOUT_DURATION

                return JsonResponse({'error': 'Invalid email or password.'}, status=401)

        except Exception as e:
            return JsonResponse({"error": str(e)}, status=400)
    else:
        return JsonResponse({'error': 'Invalid request method'}, status=400)


@api_view(["POST"])
@permission_classes([AllowAny])
def superadmin_google_login(request):
    """Logs in a super admin user using Google OAuth 2.0.

    Args:
        request (HttpRequest): The HTTP request object containing the Google ID token.

    Returns:
        Response: A DRF Response with username and token on success, or an error message on failure.
    """
    try:
        data = request.data
        token = data.get("token")

        if not token:
            return Response({"error": "Google token is required"}, status=400)

        try:
            client_id = os.environ.get('GOOGLE_OAUTH2_CLIENT_ID') or settings.GOOGLE_OAUTH2_CLIENT_ID
            if not client_id:
                logger.error("Google OAuth client ID not configured")
                return Response(
                    {"error": "Google authentication not properly configured"},
                    status=500)

            idinfo = id_token.verify_oauth2_token(
                token, google_requests.Request(), client_id)

            email = idinfo['email']

            if not idinfo.get('email_verified', False):
                return Response({"error": "Email not verified by Google"}, status=400)

            super_admin_user = superadmin_collection.find_one({"email": email})

            if not super_admin_user:
                return Response({
                    "error": "No account found with this Google email. "
                             "Please login with username and password or contact administrator.",
                }, status=404)

            tokens = generate_tokens_superadmin(
                (super_admin_user["_id"])
            )

            admin_collection.update_one({'email': email}, {'$set': {'last_login': datetime.now()}})

            response = {
                "username": super_admin_user["name"],
                "token": tokens,
                'last_login': datetime.now()
            }

            return JsonResponse(response, status=200, safe=False)

        except ValueError as e:
            logger.error(f"Invalid Google token: {e}")
            return Response({"error": "Invalid Google token"}, status=401)

    except Exception as e:
            logger.error(f"Google login error: {e}")
            return Response({"error": "An unexpected error occurred"}, status=500)

@csrf_exempt
@api_view(["POST"])
def toggle_auto_approval(request):
    """Toggles the auto-approval setting for jobs.

    Args:
        request (HttpRequest): The HTTP request object containing the new auto-approval status.

    Returns:
        JsonResponse: A JSON response indicating success or failure.
    """
    try:
        data = json.loads(request.body)
        is_auto_approval = data.get("is_auto_approval", False)

        superadmin_collection.update_one(
            {"key": "auto_approval"},
            {"$set": {"value": is_auto_approval}},
            upsert=True
        )

        return JsonResponse(
            {"message": "Auto-approval setting updated successfully"}, status=200)

    except Exception as e:
        return JsonResponse({"error": str(e)}, status=500)


@csrf_exempt
@api_view(["GET"])
def get_auto_approval_status(request):
    """Retrieves the current auto-approval status.

    Args:
        request (HttpRequest): The HTTP request object.

    Returns:
        JsonResponse: A JSON response containing the auto-approval status.
    """
    try:
        auto_approval_setting = superadmin_collection.find_one(
            {"key": "auto_approval"})
        is_auto_approval = (
            auto_approval_setting.get("value", False)
            if auto_approval_setting else False
        )
        return JsonResponse({"is_auto_approval": is_auto_approval}, status=200)
    except Exception as e:
        return JsonResponse({"error": str(e)}, status=500)

@csrf_exempt
def get_all_jobs_and_internships(request):
    """Retrieves statistics for all jobs and internships.

    Args:
        request (HttpRequest): The HTTP request object.

    Returns:
        JsonResponse: A JSON response containing statistics and lists of jobs/internships, or an error message.
    """
    try:
        jobs = list(job_collection.find())
        total_jobs = len(jobs)
        job_pending_requests = sum(
            1 for job in jobs if job.get("is_publish") is None)
        job_rejected_count = sum(
            1 for job in jobs if job.get("is_publish") is False)

        for job in jobs:
            job["_id"] = str(job["_id"])
            if "job_data" in job and "job_location" in job["job_data"]:
                job["job_data"]["location"] = job["job_data"].pop("job_location")
            total_views = len(job.get("views", []))
            job.pop("views", None)
            job["views"] = total_views

        internships = list(internship_collection.find())
        total_internships = len(internships)
        internship_pending_requests = sum(
            1 for internship in internships if internship.get("is_publish") is None)
        internship_rejected_count = sum(
            1 for internship in internships if internship.get("is_publish") is False)

        for internship in internships:
            internship["_id"] = str(internship["_id"])
            total_views = len(internship.get("views", []))
            internship.pop("views", None)
            internship["views"] = total_views

        pending_requests = job_pending_requests + internship_pending_requests
        rejected_count = job_rejected_count + internship_rejected_count

        return JsonResponse({
            "jobs": jobs,
            "internships": internships,
            "total_jobs": total_jobs,
            "total_internships": total_internships,
            "pending_requests": pending_requests,
            "rejected_count": rejected_count
        }, status=200)
    except Exception as e:
        return JsonResponse({"error": str(e)}, status=500)




@csrf_exempt
def get_jobs(request):
    """Retrieves jobs, achievements and exam based on the admin user's ID and their statistics

    Args:
        request (HttpRequest): The HTTP request object.

    Returns:
        JsonResponse: A JSON response containing a list of jobs with their approval stats or an error message.
    """
    if request.method == 'GET':
        auth_header = request.headers.get('Authorization')
        if not auth_header or not auth_header.startswith("Bearer "):
            return JsonResponse({'error': 'JWT token missing or invalid'}, status=401)

        jwt_token = auth_header.split(" ")[1]

        try:
            decoded_token = jwt.decode(jwt_token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
            admin_user = decoded_token.get('admin_user')

            jobs_list = []
            achievements_list = []
            exams_list = []  # Initialize a list for exams
            studymaterial_list = []

            # Counters for job, internship, and exam approvals, rejections, pending, and total achievements
            total_jobs = 0
            total_internships = 0
            total_achievements = 0
            total_exams = 0  # Counter for exams
            total_studymaterials = 0
            approvals = 0
            rejections = 0
            pending = 0

            # Fetch jobs
            jobs = job_collection.find({'admin_id': admin_user})
            for job in jobs:
                job['_id'] = str(job['_id'])
                job['type'] = 'job'

                # Rename 'job_location' to 'location' if it exists
                if "job_data" in job and "job_location" in job["job_data"]:
                    job["job_data"]["location"] = job["job_data"].pop("job_location")

                # Calculate total views for jobs
                total_views = len(job.get("views", []))
                job.pop("views", None)
                job["views"] = total_views

                # Update approval status count
                if job.get("is_publish") is True:
                    approvals += 1
                elif job.get("is_publish") is False:
                    rejections += 1
                else:
                    pending += 1

                total_jobs += 1
                jobs_list.append(job)

            # Fetch internships
            internships = internship_collection.find({'admin_id': admin_user})
            for internship in internships:
                internship['_id'] = str(internship['_id'])
                internship['type'] = 'internship'

                # Calculate total views for internships
                total_views = len(internship.get("views", []))
                internship.pop("views", None)
                internship["views"] = total_views

                # Update approval status count
                if internship.get("is_publish") is True:
                    approvals += 1
                elif internship.get("is_publish") is False:
                    rejections += 1
                else:
                    pending += 1

                total_internships += 1
                jobs_list.append(internship)

            # Fetch achievements
            achievements = achievement_collection.find({'admin_id': admin_user})
            for achievement in achievements:
                achievement['_id'] = str(achievement['_id'])
                achievement['type'] = 'achievement'
                achievements_list.append(achievement)
                total_achievements += 1  # Count total achievements
                
            studymaterial = study_material_collection.find({'admin_id': admin_user})
            for study in studymaterial: 
                study['_id'] = str(study['_id'])
                study['type'] = 'studymaterial'
                studymaterial_list.append(study)
                total_studymaterials += 1   

            # Fetch exams
            exams = exam_collection.find({'$or': [{'admin_id': admin_user}, {'superadmin_id': admin_user}]})
            for exam in exams:
                exam['_id'] = str(exam['_id'])
                exam['type'] = 'exam'

                # Update approval status count
                if exam.get("is_publish") is True:
                    approvals += 1
                elif exam.get("is_publish") is False:
                    rejections += 1
                else:
                    pending += 1

                total_exams += 1
                exams_list.append(exam)

            return JsonResponse({
                'jobs': jobs_list,
                'achievements': achievements_list,
                'exams': exams_list,  # Add exams to the response
                'studymaterials': studymaterial_list,
                'approvals': approvals,
                'rejections': rejections,
                'pending': pending,
                'total_jobs': total_jobs,
                'total_internships': total_internships,
                'total_achievements': total_achievements,
                'total_exams': total_exams  # Add total exams count
               # Added total achievements count
            }, status=200)

        except jwt.ExpiredSignatureError:
            return JsonResponse({'error': 'JWT token has expired'}, status=401)
        except jwt.InvalidTokenError as e:
            return JsonResponse({'error': f'Invalid JWT token: {str(e)}'}, status=401)
        except Exception as e:
            return JsonResponse({'error': f'An error occurred: {str(e)}'}, status=400)

    return JsonResponse({'error': 'Invalid request method'}, status=405)

@csrf_exempt
def get_item(request, id):
    """Retrieves all jobs, achievements and exam based on the admin id and their statistics

    Args:
        request (HttpRequest): The HTTP request object.

    Returns:
        JsonResponse: A JSON response containing a list of items with their approval stats or an error message.
    """
    if request.method == 'GET':
        try:
            admin_id = id

            jobs_list = []
            achievements_list = []
            exams_list = []  # Initialize a list for exams
            studymaterial_list = []

            # Counters for job, internship, and exam approvals, rejections, pending, and total achievements
            total_jobs = 0
            total_internships = 0
            total_achievements = 0
            total_exams = 0  # Counter for exams
            total_studymaterials = 0
            approvals = 0
            rejections = 0
            pending = 0

            # Fetch jobs
            jobs = job_collection.find({'admin_id': admin_id})
            for job in jobs:
                job['_id'] = str(job['_id'])
                job['type'] = 'job'

                # Rename 'job_location' to 'location' if it exists
                if "job_data" in job and "job_location" in job["job_data"]:
                    job["job_data"]["location"] = job["job_data"].pop("job_location")

                # Calculate total views for jobs
                total_views = len(job.get("views", []))
                job.pop("views", None)
                job["views"] = total_views

                # Update approval status count
                if job.get("is_publish") is True:
                    approvals += 1
                elif job.get("is_publish") is False:
                    rejections += 1
                else:
                    pending += 1

                total_jobs += 1
                jobs_list.append(job)

            # Fetch internships
            internships = internship_collection.find({'admin_id': admin_id})
            for internship in internships:
                internship['_id'] = str(internship['_id'])
                internship['type'] = 'internship'

                # Calculate total views for internships
                total_views = len(internship.get("views", []))
                internship.pop("views", None)
                internship["views"] = total_views

                # Update approval status count
                if internship.get("is_publish") is True:
                    approvals += 1
                elif internship.get("is_publish") is False:
                    rejections += 1
                else:
                    pending += 1

                total_internships += 1
                jobs_list.append(internship)

            # Fetch achievements
            achievements = achievement_collection.find({'admin_id': admin_id})
            for achievement in achievements:
                achievement['_id'] = str(achievement['_id'])
                achievement['type'] = 'achievement'
                achievements_list.append(achievement)
                total_achievements += 1  # Count total achievements
                
            studymaterial = study_material_collection.find({'admin_id': admin_id})
            for study in studymaterial: 
                study['_id'] = str(study['_id'])
                study['type'] = 'studymaterial'
                studymaterial_list.append(study)
                total_studymaterials += 1   

            # Fetch exams
            exams = exam_collection.find({'$or': [{'admin_id': admin_id}]})
            for exam in exams:
                exam['_id'] = str(exam['_id'])
                exam['type'] = 'exam'

                # Update approval status count
                if exam.get("is_publish") is True:
                    approvals += 1
                elif exam.get("is_publish") is False:
                    rejections += 1
                else:
                    pending += 1

                total_exams += 1
                exams_list.append(exam)

            return JsonResponse({
                'jobs': jobs_list,
                'achievements': achievements_list,
                'exams': exams_list,  # Add exams to the response
                'studymaterials': studymaterial_list,
                'approvals': approvals,
                'rejections': rejections,
                'pending': pending,
                'total_jobs': total_jobs,
                'total_internships': total_internships,
                'total_achievements': total_achievements,
                'total_exams': total_exams  # Add total exams count
               # Added total achievements count
            }, status=200)

        except jwt.ExpiredSignatureError:
            return JsonResponse({'error': 'JWT token has expired'}, status=401)
        except jwt.InvalidTokenError as e:
            return JsonResponse({'error': f'Invalid JWT token: {str(e)}'}, status=401)
        except Exception as e:
            return JsonResponse({'error': f'An error occurred: {str(e)}'}, status=400)

    return JsonResponse({'error': 'Invalid request method'}, status=405)

#===================================================================Admin-Mails====================================================================== 

@csrf_exempt
def get_admin_inbox(request):
    """Retrieves items associated with the admin that have created it jobs, achievements ,internship.

    Args:
        request (HttpRequest): The HTTP request object.

    Returns:
        JsonResponse: A JSON response containing a list of jobs or an error message.
    """
    if request.method == "GET":
        # Retrieve JWT token from Authorization header
        auth_header = request.headers.get('Authorization')
        if not auth_header or not auth_header.startswith('Bearer '):
            return JsonResponse({'error': 'JWT token missing'}, status=401)

        jwt_token = auth_header.split(' ')[1]

        try:
            # Decode the JWT token
            decoded_token = jwt.decode(jwt_token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
            admin_id = decoded_token.get('admin_user')

            # Check if admin_id is present in the token
            if not admin_id:
                return JsonResponse({"error": "Invalid token: No admin_id"}, status=401)

            # Fetch jobs, internships, achievements, and study materials from MongoDB where admin_id matches
            jobs = list(job_collection.find({"admin_id": admin_id}))
            internships = list(internship_collection.find({"admin_id": admin_id}))
            achievements = list(achievement_collection.find({"admin_id": admin_id}))
            exam = list(exam_collection.find({"admin_id": admin_id}))
            study_materials = list(study_material_collection.find({"admin_id": admin_id}))

            # Convert MongoDB ObjectId to string for JSON serialization
            def convert_objectid_to_str(items):
                for item in items:
                    item["_id"] = str(item["_id"])  # Convert ObjectId to string
                return items

            return JsonResponse({
                "jobs": convert_objectid_to_str(jobs),
                "internships": convert_objectid_to_str(internships),
                "achievements": convert_objectid_to_str(achievements),
                "exam": convert_objectid_to_str(exam),
                "study_materials": convert_objectid_to_str(study_materials),
            }, safe=False, status=200)

        except jwt.ExpiredSignatureError:
            return JsonResponse({"error": "Token has expired"}, status=401)
        except jwt.InvalidTokenError:
            return JsonResponse({"error": "Invalid token"}, status=401)
        except Exception as e:
            return JsonResponse({"error": f"Server error: {str(e)}"}, status=500)

    return JsonResponse({"error": "Invalid request method"}, status=405)

@csrf_exempt
def submit_feedback(request):
    """Submits feedback on a job, internship, achievement, or exam.

    Args:
        request (HttpRequest): The HTTP request object containing the feedback and item details.

    Returns:
        JsonResponse: A JSON response indicating success or failure.
    """
    if request.method == "POST":
        try:
            auth_header = request.headers.get('Authorization')
            if not auth_header or not auth_header.startswith('Bearer '):
                return JsonResponse({'error': 'Invalid token'}, status=401)

            token = auth_header.split(' ')[1]
            decoded_token = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])

            data = json.loads(request.body)
            item_id = data.get('item_id')
            item_type = data.get('item_type')
            feedback = data.get('feedback')

            if not item_id or not item_type or not feedback:
                return JsonResponse({'error': 'Missing required fields'}, status=400)

            if item_type == "job":
                collection = job_collection
            elif item_type == "internship":
                collection = internship_collection
            elif item_type == "achievement":
                collection = achievement_collection
            elif item_type == "exam":
                collection = exam_collection
            else:
                return JsonResponse({'error': 'Invalid item type'}, status=400)

            item_data = collection.find_one({'_id': ObjectId(item_id)})
            if not item_data:
                return JsonResponse(
                    {'error': f'Invalid item_id: {item_type.capitalize()} not found'},
                    status=404)

            admin_id = item_data.get('admin_id')
            item_name = (
                item_data.get('job_data', {}).get('title') or
                item_data.get('internship_data', {}).get('title') or
                item_data.get('name')
            )

            if not admin_id:
                return JsonResponse(
                    {'error': 'admin_id not found for the provided item'}, status=404)

            review_document = {
                'admin_id': admin_id,
                'item_id': item_id,
                'item_name': item_name,
                'item_type': item_type,
                'feedback': feedback,
                'timestamp': datetime.now().isoformat()
            }
            reviews_collection.insert_one(review_document)

            collection.update_one(
                {'_id': ObjectId(item_id)},
                {'$set': {'is_publish': False}}
            )

            return JsonResponse(
                {'message': 'Feedback submitted successfully and item unpublished'},
                status=200)

        except jwt.ExpiredSignatureError:
            return JsonResponse({"error": "Token has expired"}, status=401)
        except jwt.InvalidTokenError:
            return JsonResponse({"error": "Invalid token"}, status=401)
        except Exception as e:
            return JsonResponse({"error": f"Server error: {str(e)}"}, status=500)

    return JsonResponse({"error": "Invalid request method"}, status=405)




def fetch_review(request):
    """Extracts JWT, validates it, and fetches all review documents for the admin ID.

    Args:
        request (HttpRequest): The HTTP request object.

    Returns:
        JsonResponse: A JSON response containing review documents or an error message.
    """
    auth_header = request.headers.get("Authorization")
    if not auth_header or not auth_header.startswith("Bearer "):
        return JsonResponse({"error": "Unauthorized access"}, status=401)

    token = auth_header.split(" ")[1]
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
    except jwt.ExpiredSignatureError:
        return JsonResponse({"error": "Token has expired"}, status=401)
    except jwt.InvalidTokenError:
        return JsonResponse({"error": "Invalid token"}, status=401)

    admin_id = payload.get("admin_user")
    if not admin_id:
        return JsonResponse({"error": "Invalid token payload"}, status=401)

    print(f"Querying for admin_id: {admin_id}")
    reviews_cursor = reviews_collection.find({"admin_id": admin_id})

    reviews_list = []
    for review in reviews_cursor:
        formatted_review = {
            "review_id": str(review["_id"]),
            "admin_id": review["admin_id"],
            "item_id": review["item_id"],
            "item_name": review.get("item_name", ""),
            "item_type": review["item_type"],
            "feedback": review["feedback"],
            "timestamp": review["timestamp"],
        }
        reviews_list.append(formatted_review)

    return JsonResponse({"reviews": reviews_list}, status=200, safe=False)


@csrf_exempt
def get_contact_messages(request):
    """Retrieves all contact messages from the database.

    Args:
        request (HttpRequest): The HTTP request object.

    Returns:
        JsonResponse: A JSON response containing contact messages or an error message.
    """
    if request.method == "GET":
        try:
            messages = list(contactus_collection.find(
                {}, {"_id": 1, "name": 1, "contact": 1, "message": 1, "timestamp": 1}))

            for message in messages:
                message["_id"] = str(message["_id"])
                if "timestamp" in message and message["timestamp"]:
                    message["timestamp"] = message["timestamp"].strftime(
                        "%Y-%m-%d %H:%M:%S")
                else:
                    message["timestamp"] = "N/A"

            return JsonResponse({"messages": messages}, status=200)

        except Exception as e:
            print(f"Error: {e}")
            return JsonResponse({"error": str(e)}, status=500)

    return JsonResponse({"error": "Invalid request method"}, status=405)


@csrf_exempt
def reply_to_message(request):
    """Replies to a contact message.

    Args:
        request (HttpRequest): The HTTP request object containing the message ID and reply message.

    Returns:
        JsonResponse: A JSON response indicating success or failure.
    """
    if request.method == "POST":
        try:
            data = json.loads(request.body)
            message_id = data.get("message_id")
            reply_message = data.get("reply_message")

            if not message_id or not reply_message:
                return JsonResponse(
                    {"error": "Message ID and reply message are required."}, status=400)

            result = contactus_collection.update_one(
                {"_id": ObjectId(message_id)},
                {"$set": {"reply_message": reply_message}}
            )

            if result.modified_count == 0:
                return JsonResponse(
                    {"error": "Message not found or already updated."}, status=404)

            return JsonResponse({"success": "Reply sent successfully!"}, status=200)

        except Exception as e:
            return JsonResponse({"error": str(e)}, status=500)

    return JsonResponse({"error": "Invalid request method."}, status=405)

@csrf_exempt
def get_student_achievements(request):
    """Retrieves all student achievements.

    Args:
        request (HttpRequest): The HTTP request object.

    Returns:
        JsonResponse: A JSON response containing a list of student achievements or an error message.
    """
    try:
        student_achievements = student_achievement_collection.find()
        achievement_list = []

        for achievement in student_achievements:
            student_name = achievement.get("name", "Unknown Student")
            achievement_desc = achievement.get("achievement_description", "No description")
            achievement_type = achievement.get("achievement_type", "Unknown Type")
            company = achievement.get("company_name", "Unknown Company")
            date_of_achievement = achievement.get("date_of_achievement", "Unknown Date")
            batch = achievement.get("batch", "Unknown Batch")
            photo = achievement.get("photo", None)

            message = (
                f"{student_name} achieved {achievement_desc} in {achievement_type} "
                f"on {date_of_achievement}"
            )

            achievement_list.append({
                "student_achievement_id": str(achievement["_id"]),
                "student_name": student_name,
                "message": message,
                "achievement_data": {
                    "description": achievement_desc,
                    "type": achievement_type,
                    "company": company,
                    "date": date_of_achievement,
                    "batch": batch,
                    "photo": photo,
                    "is_approved": achievement.get("is_approved", False),
                },
                "timestamp": achievement.get("submitted_at", ""),
            })

        return JsonResponse({"student_achievements": achievement_list}, status=200)

    except Exception as e:
        return JsonResponse({"error": str(e)}, status=500)


@csrf_exempt
def get_admin_details(request, userId):
    """Retrieves details for a specific admin user.

    Args:
        request (HttpRequest): The HTTP request object.
        userId (str): The ID of the admin user to retrieve.

    Returns:
        JsonResponse: A JSON response containing admin details or an error message.
    """
    if request.method == "GET":
        try:
            admin = admin_collection.find_one({"_id": ObjectId(userId)})

            if not admin:
                return JsonResponse(
                    {"error": "Admin with this ID does not exist"}, status=400)

            profile_image = admin.get("profile_image", "default.png")

            data = {
                "name": admin.get("name"),
                "email": admin.get("email"),
                "status": admin.get("status"),
                "created_at": str(admin.get("created_at")) if admin.get("created_at") else "N/A",
                "last_login": str(admin.get("last_login")) if admin.get("last_login") else "Never",
                "college_name": admin.get("college_name", "N/A"),
                "department": admin.get("department", "N/A"),
                "contact_number": admin.get("mobile_number", "N/A"),
                "role": "admin",
                "profile_image": profile_image,
            }

            return JsonResponse({"message": "Admin details found", "data": data}, status=200)

        except Exception as e:
            return JsonResponse({"error": str(e)}, status=400)
    else:
        return JsonResponse({"error": "Invalid request method"}, status=400)

@csrf_exempt
def update_admin_profile(request, userId):
    """Updates the profile information for a specific admin user.

    Args:
        request (HttpRequest): The HTTP request object containing updated admin profile data.
        userId (str): The ID of the admin user to update.

    Returns:
        JsonResponse: A JSON response indicating success or failure.
    """
    if request.method == "PUT":
        try:
            data = json.loads(request.body)

            admin = admin_collection.find_one({"_id": ObjectId(userId)})
            if not admin:
                return JsonResponse({"error": "Admin not found"}, status=404)

            data.pop("email", None)

            updated_fields = {
                "name": data["name"],
                "college_name": data["college_name"],
                "department": data["department"]
            }

            admin_collection.update_one({"_id": ObjectId(userId)}, {"$set": updated_fields})

            return JsonResponse(
                {"message": "Admin profile updated successfully"}, status=200)

        except Exception as e:
            return JsonResponse({"error": str(e)}, status=400)
    else:
        return JsonResponse({"error": "Invalid request method"}, status=400)

@csrf_exempt
def get_superadmin_details(request, userId):
    """Retrieves details for a specific super admin user.

    Args:
        request (HttpRequest): The HTTP request object.
        userId (str): The ID of the super admin user to retrieve.

    Returns:
        JsonResponse: A JSON response containing super admin details or an error message.
    """
    if request.method == "GET":
        try:
            superadmin = superadmin_collection.find_one({"_id": ObjectId(userId)})

            if not superadmin:
                return JsonResponse(
                    {"error": "Super Admin with this ID does not exist"}, status=400
                )

            profile_image = ""
            if "profile_image" in superadmin:
                if isinstance(superadmin["profile_image"], bytes):
                    profile_image = "data:image/jpeg;base64," + base64.b64encode(
                        superadmin["profile_image"]).decode('utf-8')
                elif isinstance(superadmin["profile_image"], str):
                    profile_image = superadmin["profile_image"]

            data = {
                "name": superadmin.get("name"),
                "email": superadmin.get("email"),
                "status": superadmin.get("status", "N/A"),
                "created_at": str(superadmin.get("created_at")) if superadmin.get("created_at") else "N/A",
                "last_login": str(superadmin.get("last_login")) if superadmin.get("last_login") else "Never",
                "college_name": superadmin.get("college_name", "N/A"),
                "department": superadmin.get("department", "N/A"),
                "role": "superadmin",
                "profile_image": profile_image,
            }

            return JsonResponse(
                {"message": "Super Admin details found", "data": data}, status=200
            )

        except Exception as e:
            return JsonResponse({"error": str(e)}, status=400)
    else:
        return JsonResponse({"error": "Invalid request method"}, status=400)
    
# @csrf_exempt
# def get_applied_students(request, application_type, application_id):
#     """
#     Fetch students who applied for a specific job, internship, or exam.

#     Parameters:
#         request (HttpRequest): The HTTP request.
#         application_type (str): Type of application ("job", "internship", "exam").
#         application_id (str): The ID of the job, internship, or exam.

#     Returns:
#         JsonResponse: List of students who applied for the specified application.
#     """
#     try:
#         # Validate the application type
#         valid_types = {"job": "applied_jobs", "internship": "applied_internships", "exam": "applied_exams"}
#         if application_type not in valid_types:
#             return JsonResponse({"error": "Invalid application type"}, status=400)

#         # Query students based on the application type and ID
#         field = valid_types[application_type]
#         query = {f"{field}.id": application_id}
#         students = list(student_collection.find(query, {"_id": 1, "name": 1, "email": 1, "department": 1}))

#         # Process the result into a list of students
#         students_list = [
#             {
#                 "id": str(student["_id"]),
#                 "name": student["name"],
#                 "email": student["email"],
#                 "department": student["department"]
#             }
#             for student in students
#         ]

#         return JsonResponse({"students": students_list}, status=200)
#     except Exception as e:
#         return JsonResponse({"error": str(e)}, status=500)


@csrf_exempt
def get_applied_students(request, entity_type, entity_id):
    """
    Fetch students who applied for a specific job, internship, or exam.
    entity_type: 'job', 'internship', 'exam'
    entity_id: ID of the entity (job, internship, or exam)
    """
    try:
        if entity_type not in ["job", "internship", "exam"]:
            return JsonResponse({"error": "Invalid entity type. Allowed types: job, internship, exam"}, status=400)

        # Match the entity type with the respective key
        entity_key_map = {
            "job": "applied_jobs",
            "internship": "applied_internships",
            "exam": "applied_exams"
        }
        entity_key = entity_key_map[entity_type]

        # Validate entity ID format
        if not ObjectId.is_valid(entity_id):
            return JsonResponse({"error": "Invalid entity ID format"}, status=400)

        # Construct the query
        query = {
            f"{entity_key}.job_id" if entity_type == "job" else f"{entity_key}.internship_id" if entity_type == "internship" else f"{entity_key}.exam_id": entity_id
        }

        # Query the students collection
        students = student_collection.find(query, {
            "_id": 1, 
            "name": 1, 
            "department": 1, 
            "year": 1, 
            "college_name": 1, 
            "email": 1, 
            "mobile_number": 1
        })

        # Format response data
        students_list = [
            {
                "id": str(student["_id"]),
                "name": student["name"],
                "department": student["department"],
                "year": student["year"],
                "college_name": student["college_name"],
                "email": student["email"],
                "mobile_number": student.get("mobile_number", "N/A")
            }
            for student in students
        ]

        if not students_list:
            return JsonResponse({
                "entity_type": entity_type,
                "entity_id": entity_id,
                "message": "No students found for this entity."
            }, status=404)

        return JsonResponse({
            "entity_type": entity_type,
            "entity_id": entity_id,
            "students": students_list
        }, safe=False, status=200)

    except Exception as e:
        # Catch any unexpected errors
        return JsonResponse({
            "error": "An unexpected error occurred.",
            "details": str(e)
        }, status=500)

  
@csrf_exempt
def increment_view_count(request, job_id):
    if request.method == "POST":
        try:
            # Parse the request payload to get the student's ObjectId
            data = json.loads(request.body)
            student_id = data.get('student_id')

            if not student_id:
                return JsonResponse({'error': 'Student ID is required'}, status=400)

            # Find the job, internship, or exam by ID in respective collections
            job = job_collection.find_one({"_id": ObjectId(job_id)})
            internship = internship_collection.find_one({"_id": ObjectId(job_id)})
            exam = exam_collection.find_one({"_id": ObjectId(job_id)})

            if job:
                # Update the views array for a job
                if student_id not in job.get('views', []):
                    job_collection.update_one(
                        {"_id": ObjectId(job_id)},
                        {"$addToSet": {"views": str(ObjectId(student_id))}}
                    )
                return JsonResponse({'message': 'View count incremented successfully for job'}, status=200)

            elif internship:
                # Update the views array for an internship
                if student_id not in internship.get('views', []):
                    internship_collection.update_one(
                        {"_id": ObjectId(job_id)},
                        {"$addToSet": {"views": str(ObjectId(student_id))}}
                    )
                return JsonResponse({'message': 'View count incremented successfully for internship'}, status=200)

            elif exam:
                # Update the views array for an exam
                if student_id not in exam.get('views', []):
                    exam_collection.update_one(
                        {"_id": ObjectId(job_id)},
                        {"$addToSet": {"views": str(ObjectId(student_id))}}
                    )
                return JsonResponse({'message': 'View count incremented successfully for exam'}, status=200)

            else:
                return JsonResponse({'error': 'Job, internship, or exam not found'}, status=404)

        except Exception as e:
            return JsonResponse({'error': str(e)}, status=400)
    else:
        return JsonResponse({'error': 'Invalid request method'}, status=400)
