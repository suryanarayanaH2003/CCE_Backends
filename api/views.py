import jwt
import json
import os
import re
from datetime import datetime, timedelta, timezone
from django.http import JsonResponse
from pymongo import MongoClient
from django.contrib.auth.hashers import make_password, check_password
from django.views.decorators.csrf import csrf_exempt
from django.core.mail import send_mail
from django.conf import settings
from bson import ObjectId, Binary
import pandas as pd
from django.core.mail import send_mail
from django.conf import settings
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from rest_framework import status
import random
import string
import traceback
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import base64
import pytz  # Add this import
import logging
import json
from django.http import JsonResponse
from datetime import datetime
import base64
from django.utils import timezone
from google.oauth2 import id_token
from google.auth.transport import requests as google_requests


from dotenv import load_dotenv
load_dotenv()

# Get MongoDB URI from .env file
MONGO_URI = os.getenv("MONGO_URI")
# Connect to MongoDB
client = MongoClient(MONGO_URI)


# Create your views here.
JWT_SECRET = "secret"
JWT_ALGORITHM = "HS256"


def generate_tokens(student_user):
    access_payload = {
        "student_user": str(student_user),
        "exp": (datetime.utcnow() + timedelta(minutes=600)).timestamp(),  # Expiration in 600 minutes
        "iat": datetime.utcnow().timestamp(),  # Issued at current time
    }
    token = jwt.encode(access_payload, JWT_SECRET, algorithm=JWT_ALGORITHM)
    return {"jwt": token}


# MongoDB connection
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
# Function to send confirmation email
def send_confirmation_email(to_email, name, password):
    subject = "Student Account Created"
    body = f"""
    Your Student account has been successfully created on the CCE platform.
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

    except Exception as e:
        print(f"Error sending email: {str(e)}")

@csrf_exempt
def student_signup(request):
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

            # Check if the email already exists
            if student_collection.find_one({"email": email}):
                return JsonResponse(
                    {"error": "Student user with this email already exists"}, status=400
                )

            # Check if email is a valid college email ID
            if "@sns" not in email:
                return JsonResponse(
                    {"error": "Please enter a valid college email ID"}, status=400
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
    
studentcollection = db["ajay"]
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


@csrf_exempt
def student_login(request):
    if request.method == "POST":
        try:
            data = json.loads(request.body)
            email = data.get("email")
            password = data.get("password")

            # Check lockout status
            if email in failed_login_attempts:
                lockout_data = failed_login_attempts[email]
                if lockout_data["count"] >= 3 and datetime.now() < lockout_data["lockout_until"]:
                    return JsonResponse(
                        {"error": "Too many failed attempts. Please try again after 2 minutes."},
                        status=403,
                    )

            # Find the student user by email
            student_user = student_collection.find_one({"email": email})
            username = student_user.get('name')
            if not student_user:
                return JsonResponse(
                    {"error": "No account found with this email"}, status=404
                )

            # Check if the account is active
            if student_user.get("status") != "active":
                return JsonResponse(
                    {"error": "This account is inactive. Please contact the admin."}, status=403
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
                return JsonResponse({"username": student_user['name'], "token": tokens}, status=200)
            else:
                # Track failed attempts
                if email not in failed_login_attempts:
                    failed_login_attempts[email] = {"count": 1, "lockout_until": None}
                else:
                    failed_login_attempts[email]["count"] += 1
                    if failed_login_attempts[email]["count"] >= 3:
                        failed_login_attempts[email]["lockout_until"] = datetime.now() + lockout_duration

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
    return ''.join(random.choices(string.digits, k=length))



@api_view(["POST"])
@permission_classes([AllowAny])
def student_forgot_password(request):
    try:
        email = request.data.get('email')
        user = student_collection.find_one({"email": email})
        if not user:
            return Response({"error": "Email not found"}, status=400)

        reset_token = generate_reset_token()
        expiration_time = datetime.utcnow() + timedelta(hours=1)

        student_collection.update_one(
            {"email": email},
            {"$set": {"password_reset_token": reset_token, "password_reset_expires": expiration_time}}
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

@csrf_exempt   
def student_verify_otp(request):
    if request.method == "POST":
        try:
            data = json.loads(request.body)
            email = data.get("email")
            otp = data.get("token")

            # Find the student user by email
            student_user = student_collection.find_one({"email": email})
            if not student_user:
                return JsonResponse(
                    {"error": "No account found with this email"}, status=404
                )
            

            # Validate the OTP
            if student_user.get("password_reset_token") == otp:
                return JsonResponse({"message": "OTP verification successful"}, status=200)
            else:
                return JsonResponse({"error": "Invalid OTP"}, status=403)

        except Exception as e:
            return JsonResponse({"error": str(e)}, status=400)
    else:
        return JsonResponse({"error": "Invalid request method"}, status=400)

@csrf_exempt
def student_reset_password(request):
    """Reset Password Function for Students"""
    if request.method == 'POST':
        try:
            # Parse the request payload
            data = json.loads(request.body)
            email = data.get('email')
            new_password = data.get('newPassword')

            # Validate the request data
            if not email or not new_password:
                return JsonResponse({"error": "Email and new password are required."}, status=400)

            # Fetch the student by email
            student = student_collection.find_one({"email": email})
            if not student:
                return JsonResponse({"error": "Student not found."}, status=404)

            # Hash the new password
            hashed_password = make_password(new_password)

            # Ensure hashed password starts with "pbkdf2_sha256$"
            if not hashed_password.startswith("pbkdf2_sha256$"):
                return JsonResponse({"error": "Failed to hash the password correctly."}, status=500)

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
                return JsonResponse({"error": "Failed to update the password in MongoDB."}, status=500)

            return JsonResponse({"message": "Password reset successfully"}, status=200)

        except Exception as e:
            return JsonResponse({"error": f"An error occurred: {str(e)}"}, status=500)

    return JsonResponse({"error": "Invalid request method. Use POST."}, status=405)
    
@csrf_exempt
def get_students(request):
    """
    API to retrieve all students.
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
def update_student(request, student_id):
    """
    API to update a student's profile, including status updates.
    """
    if request.method == 'PUT':
        try:
            data = json.loads(request.body)
            student = student_collection.find_one({'_id': ObjectId(student_id)})
            if not student:
                return JsonResponse({'error': 'Student not found'}, status=404)

            # ✅ Add "status" to allowed fields
            allowed_fields = ['name', 'department', 'year', 'college_name', 'status']

            # Filter data to include only allowed fields
            update_data = {field: data[field] for field in allowed_fields if field in data}

            if update_data:
                # Update student in MongoDB
                student_collection.update_one({'_id': ObjectId(student_id)}, {'$set': update_data})
                return JsonResponse({'message': 'Student details updated successfully'}, status=200)
            else:
                return JsonResponse({'error': 'No valid fields provided for update'}, status=400)

        except Exception as e:
            return JsonResponse({'error': str(e)}, status=500)
    else:
        return JsonResponse({'error': 'Invalid request method'}, status=400)


@csrf_exempt
def delete_student(request, student_id):
    """
    API to delete a student.
    """
    if request.method == 'DELETE':
        try:
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
    
#===============================================================Profile=======================================================================

@csrf_exempt
def get_profile(request, userId):
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
def update_profile(request, userId):
    if request.method == "PUT":
        try:
            # Parse JSON request body
            data = json.loads(request.body)

            # Find the student user by ID
            user = student_collection.find_one({"_id": ObjectId(userId)})
            if not user:
                return JsonResponse({"error": "User not found"}, status=404)

            # Prevent email from being changed
            data.pop("email", None)

            # Update only the name
            updated_fields = {key: value for key, value in data.items() if key == "name"}
            if updated_fields:
                student_collection.update_one(
                    {"_id": ObjectId(userId)}, {"$set": updated_fields}
                )

            return JsonResponse({"message": "Profile updated successfully"}, status=200)

        except Exception as e:
            return JsonResponse({"error": str(e)}, status=400)
    else:
        return JsonResponse({"error": "Invalid request method"}, status=400)
    
@csrf_exempt
def update_superadmin_profile(request, userId):
    if request.method == "PUT":
        try:
            # Parse JSON request body
            data = json.loads(request.body)

            # Find the super admin user by ID
            super_admin = superadmin_collection.find_one({"_id": ObjectId(userId)})
            if not super_admin:
                return JsonResponse({"error": "SuperAdmin not found"}, status=404)

            # Validate request payload
            if "name" not in data:
                return JsonResponse({"error": "Missing required fields"}, status=400)

            # Prevent email from being changed
            data.pop("email", None)

            # Update only the name
            updated_fields = {
                "name": data["name"]
            }

            superadmin_collection.update_one({"_id": ObjectId(userId)}, {"$set": updated_fields})

            return JsonResponse({"message": "SuperAdmin profile updated successfully"}, status=200)

        except Exception as e:
            return JsonResponse({"error": str(e)}, status=400)
    else:
        return JsonResponse({"error": "Invalid request method"}, status=400)

       
#================================================================Jobs================================================================================================
@csrf_exempt
def save_job(request, pk):
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
def unsave_job(request, pk):
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
def get_saved_jobs(request, user_id):
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

    
#============================================================================ Internships =============================================================================================
@csrf_exempt
def save_internship(request, pk):
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
def unsave_internship(request, pk):
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
def get_saved_internships(request, user_id):
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
@api_view(['POST'])
def post_student_achievement(request):
    """
    Handles submission of student achievements with file uploads.
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
            JWT_SECRET,
            algorithms=[JWT_ALGORITHM],
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
def review_achievement(request, achievement_id):
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
def get_all_study_material(request):
    """
    Fetch a single study material by its ID.
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
def job_click(request):
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


#================================================================Applied Jobs================================================================================================


@csrf_exempt
def apply_job(request):
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
def confirm_job(request):
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
def get_applied_jobs(request, userId):
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

# ========================== Exams =============================================================================================


@csrf_exempt
def exam_post(request):
    if request.method == 'POST':
        try:
            # Decode the raw request body
            exam_data = request.POST.get('exam_data')
            role = request.POST.get('role')
            user_id = request.POST.get('userId')

            if not exam_data:
                return JsonResponse({"error": "Missing exam_data field in request"}, status=400)

            try:
                data = json.loads(exam_data)
            except json.JSONDecodeError:
                return JsonResponse({"error": "Invalid JSON format in exam_data"}, status=400)

            # Extract exam_title from exam_data, fallback to top-level
            exam_title = data.get('exam_title')
            logger.info("exam_title extracted: %s", exam_title)

            exam_link = data.get('exam_link')

            # Validate required fields
            required_fields = ['exam_title','about_exam', 'syllabus','result','application_process', 'documents_required','application_deadline']
            missing_fields = [field for field in required_fields if field not in data or not data[field]]
            if missing_fields:
                return JsonResponse({"error": f"Missing required fields: {', '.join(missing_fields)}"}, status=400)

            # Extract and validate application_deadline
            application_deadline_str = data.get('application_deadline')
            logger.info("application_deadline_str: %s", application_deadline_str)

            if not application_deadline_str:
                return JsonResponse({"error": "Missing required field: application_deadline"}, status=400)

            # Handle date string (could be "2025-03-21" or "2025-03-21T00:00:00.000Z")
            def parse_date(date_str):
                if not date_str:
                    return None
                try:
                    if 'T' in date_str:
                        date_str = date_str.split('T')[0]
                    return datetime.strptime(date_str, "%Y-%m-%d").replace(tzinfo=pytz.utc)
                except ValueError:
                    return None

            application_deadline = parse_date(application_deadline_str)
            if not application_deadline:
                return JsonResponse({"error": "Invalid date format for application_deadline. Use YYYY-MM-DD."}, status=400)

            # Auto-approval logic
            auto_approval_setting = superadmin_collection.find_one({"key": "auto_approval"})
            is_auto_approval = auto_approval_setting.get("value", False) if auto_approval_setting else False
            is_publish = True if role == 'superadmin' or (role == 'admin' and is_auto_approval) else None

            # Handle optional image upload if included
            image = request.FILES.get('image')
            image_base64 = None
            if image:
                try:
                    image_base64 = base64.b64encode(image.read()).decode('utf-8')
                except Exception as e:
                    logger.error("Error processing image: %s", str(e))
                    return JsonResponse({"error": "Error processing image file"}, status=400)

            # Transform cutoff array of objects into a dictionary
            cutoff_array = data.get('cutoff', [])
            cutoff_dict = {}
            for item in cutoff_array:
                if isinstance(item, dict):
                    cutoff_dict.update(item)  # Merge each object's key-value pair
            logger.info("cutoff transformed: %s", cutoff_dict)

            # Check current status based on deadline
            now = timezone.now()
            current_status = "Active" if application_deadline >= now else "Expired"

            # Transform exam_highlights array of objects into a dictionary
            highlights_array = data.get('exam_highlights', [])
            highlights_dict = {}
            for item in highlights_array:
                if isinstance(item, dict):
                    highlights_dict.update(item)  # Merge each object's key-value pair
            logger.info("exam_highlights transformed: %s", highlights_dict)

            # Construct exam post document with all fields
            exam_post = {
                "exam_data": {
                    "exam_title": exam_title,
                    "exam_link": exam_link,
                    "about_exam": data.get('about_exam', ""),
                    "exam_highlights": highlights_dict,
                    "eligibility_criteria": data.get('eligibility_criteria', ""),
                    "application_process": data.get('application_process', ""),
                    "documents_required": data.get('documents_required', ""),
                    "exam_centers": data.get('exam_centers', ""),
                    "exam_pattern": data.get('exam_pattern', ""),
                    "mock_test": data.get('mock_test', ""),
                    "admit_card": data.get('admit_card', ""),
                    "preparation_tips": data.get('preparation_tips', ""),
                    "result": data.get('result', ""),
                    "answer_key": data.get('answer_key', ""),
                    "exam_analysis": data.get('exam_analysis', ""),
                    "cutoff": cutoff_dict,
                    "selection_process": data.get('selection_process', ""),
                    "question_paper": data.get('question_paper', ""),
                    "faq": data.get('faq', ""),
                    "application_deadline": application_deadline.isoformat(),
                    "syllabus": data.get('syllabus', ""),
                    "participating_institutes": data.get('participating_institutes', ""),
                    "image": image_base64
                },
                "admin_id" if role == "admin" else "superadmin_id": user_id,
                "is_publish": is_publish,
                "status": current_status,
                "updated_at": timezone.now().isoformat()
            }

            # Log the full document before insertion
            logger.info("Full exam_post document: %s", json.dumps(exam_post, default=str))

            # Insert into MongoDB exam_collection
            exam_collection.insert_one(exam_post)
            logger.info("Data inserted into exam_collection with _id: %s", str(exam_post['_id']))

            return JsonResponse({"message": "Exam posted successfully, awaiting approval if posted by admin."}, status=200)

        except json.JSONDecodeError as e:
            logger.error("JSON parsing error: %s", str(e))
            return JsonResponse({"error": "Invalid JSON format"}, status=400)
        except Exception as e:
            logger.error("Error: %s", str(e))
            return JsonResponse({"error": str(e)}, status=500)

    return JsonResponse({"error": "Invalid request method. Only POST is allowed."}, status=405)



@csrf_exempt
def get_published_exams(request):
    try:
        # Find all published exams
        exams = exam_collection.find({"is_publish": True})
        exam_list = []

        for exam in exams:
            exam["_id"] = str(exam["_id"]) 
            
            # Ensure 'views' is a list before calculating total views
            views = exam.get("views", [])
            if not isinstance(views, list):
                views = []  # Default to an empty list if data is corrupted
            
            total_views = len(views)
            exam["views"] = total_views

            exam_list.append(exam)

        # ✅ Return an empty array instead of a 404 error
        return JsonResponse({"exams": exam_list}, status=200)

    except Exception as e:
        logger.error("Error fetching published exams: %s", str(e))
        return JsonResponse({"error": str(e)}, status=500)

# @csrf_exempt
# def get_exams_with_admin(request):
#     """
#     Fetch all exams and map them with admin names.
#     """
#     try:
#         # Fetch all exam from the exams collection
#         exams = exam_collection.find({}, {"_id": 1, "admin_id": 1, "superadmin_id": 1, "exam_data": 1, "updated_at": 1})

#         exam_list = []
        
#         for exam in exams:
#             exam["_id"] = str(exam["_id"])  # Convert ObjectId to string
#             exam["updated_at"] = exam.get("updated_at", "N/A")

#             # Fetch admin details using admin_id
#             admin_id = exam.get("admin_id")
#             superadmin_id = exam.get("superadmin_id")
            
#             if admin_id:
#                 admin = admin_collection.find_one({"_id": ObjectId(admin_id)}, {"name": 1})
#                 admin_name = admin.get("name", "Unknown Admin") if admin else "Unknown Admin"
#             elif superadmin_id:
#                 superadmin = superadmin_collection.find_one({"_id": ObjectId(superadmin_id)}, {"name": 1})
#                 admin_name = superadmin.get("name", "Unknown Superadmin") if superadmin else "Unknown Superadmin"
#             else:
#                 admin_name = "Unknown Admin"
            
      
#             # Append job details with mapped admin name
#             exam_list.append({
#                 "admin_name": admin_name,
#                 "message": f"{admin_name} posted a exam",
#                 "exam_data": exam.get("exam_data", {}),
#                 "timestamp": exam["updated_at"]
#             })

#         return JsonResponse({"exams": exam_list}, status=200)

#     except Exception as e:
#         return JsonResponse({"error": str(e)}, status=500)

       
@csrf_exempt
def save_exam(request, pk):
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
                {"$addToSet": {"saved_exam": pk}},
            )

            return JsonResponse({"message": "Exam saved successfully"})
        except Exception as e:
            return JsonResponse({"error": str(e)}, status=status.HTTP_400_BAD_REQUEST)


@csrf_exempt
def unsave_exam(request, pk):
    if request.method == "POST":
        try:
            data = json.loads(request.body)
            user_id = data.get("userId")

            if not user_id:
                return JsonResponse(
                    {"error": "User ID is required"}, status=status.HTTP_400_BAD_REQUEST
                )

            student_collection.update_one(
                {"_id": ObjectId(user_id)}, {"$pull": {"saved_exam": pk}}
            )

            return JsonResponse({"message": "Exam removed from saved"})
        except Exception as e:
            return JsonResponse({"error": str(e)}, status=status.HTTP_400_BAD_REQUEST)
        
@csrf_exempt
def get_saved_exams(request, user_id):
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

        saved_exams = user.get("saved_exam", [])

        exams = []
        for exam_id in saved_exams:
            if not ObjectId.is_valid(exam_id):
                continue  # Skip invalid ObjectIds

            exam = exam_collection.find_one({"_id": ObjectId(exam_id)})
            if exam:
                exam["_id"] = str(exam["_id"])
                exams.append(exam)
        
        return JsonResponse({"message": "Saved exams retrieved successfully", "exams": exams})
        
    except Exception as e:
        return JsonResponse({"error": str(e)}, status=status.HTTP_400_BAD_REQUEST)
    

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


#====================exam--maria=============#
@csrf_exempt
def get_exams(request):
    try:
        exams = exam_collection.find()
        exam_list = []

        for exam in exams:
            exam["_id"] = str(exam["_id"])  # Convert ObjectId to string

            # Convert is_publish to readable status
            approval_status = "Waiting for Approval" if exam.get("is_publish") is None else (
                "Approved" if exam["is_publish"] else "Rejected"
            )

            # Fetch admin details using admin_id
            admin_id = exam.get("admin_id")
            admin_name = "Super Admin"
            if admin_id:
                admin = admin_collection.find_one({"_id": ObjectId(admin_id)})
                if admin:
                    admin_name = admin.get("name", "Super Admin")

            # Add human-readable approval status and admin name
            exam["approval_status"] = approval_status
            exam["admin_name"] = admin_name  # Attach admin name

            exam_list.append(exam)

        return JsonResponse({"exams": exam_list}, status=200, safe=False)

    except Exception as e:
        return JsonResponse({"error": str(e)}, status=500)

#APPROVED EXAMS code

@csrf_exempt
def review_exam(request, exam_id):
    """
    Review an exam by approving or rejecting it based on the exam ID.
    """
    if request.method == "POST":
        try:
            # Parse the request body
            data = json.loads(request.body)
            action = data.get("action")

            # Validate the action
            if action not in ["approve", "reject"]:
                return JsonResponse({"error": "Invalid action"}, status=400)

            # Find the exam by ID
            exam = exam_collection.find_one({"_id": ObjectId(exam_id)})
            if not exam:
                return JsonResponse({"error": "Exam not found"}, status=404)

            # Update the is_publish field based on the action
            is_publish = True if action == "approve" else False
            exam_collection.update_one(
                {"_id": ObjectId(exam_id)},
                {"$set": {"is_publish": is_publish, "updated_at": datetime.now()}}
            )

            # Return a success message
            message = "Exam approved and published successfully" if is_publish else "Exam rejected successfully"
            return JsonResponse({"message": message}, status=200)

        except Exception as e:
            logger.error("Error reviewing exam: %s", str(e))
            return JsonResponse({"error": str(e)}, status=400)

    return JsonResponse({"error": "Invalid request method"}, status=405)

@csrf_exempt
def update_exam(request, exam_id):
    """
    Update an exam by its ID.
    """
    if request.method == 'PUT':
        try:
            # Parse the request body
            data = json.loads(request.body)

            # Find the exam by ID
            exam = exam_collection.find_one({"_id": ObjectId(exam_id)})
            if not exam:
                return JsonResponse({"error": "Exam not found"}, status=404)

            # Exclude the _id field from the update
            if '_id' in data:
                del data['_id']

            # Prepare the update data for nested fields
            update_data = {"$set": {f"exam_data.{key}": value for key, value in data.items()}}

            # Update the exam document
            exam_collection.update_one({"_id": ObjectId(exam_id)}, update_data)

            # Fetch the updated exam document
            updated_exam = exam_collection.find_one({"_id": ObjectId(exam_id)})
            updated_exam["_id"] = str(updated_exam["_id"])  # Convert ObjectId to string

            return JsonResponse({"exam": updated_exam}, status=200)

        except Exception as e:
            logger.error("Error updating exam: %s", str(e))
            return JsonResponse({"error": str(e)}, status=500)

    return JsonResponse({"error": "Invalid request method"}, status=405)

@csrf_exempt
def get_exam_id(request, exam_id):
    """
    Get an exam by its ID.
    """
    if request.method == 'GET':
        try:
            exam = exam_collection.find_one({"_id": ObjectId(exam_id)})
            if not exam:
                return JsonResponse({"error": "Exam not found"}, status=404)

            exam["_id"] = str(exam["_id"])  # Convert ObjectId to string

            # Convert application_deadline to only date format (YYYY-MM-DD)
            if "application_deadline" in exam and exam["application_deadline"]:
                if isinstance(exam["application_deadline"], datetime):  # If it's a datetime object
                    exam["application_deadline"] = exam["application_deadline"].strftime("%Y-%m-%d")
                else:  # If it's a string, ensure it's correctly formatted
                    try:
                        exam["application_deadline"] = datetime.strptime(exam["application_deadline"], "%Y-%m-%dT%H:%M:%S").strftime("%Y-%m-%d")
                    except ValueError:
                        pass  # Ignore if the format is unexpected

            return JsonResponse({"exam": exam}, status=200)
        except Exception as e:
            return JsonResponse({"error": str(e)}, status=500)
    else:
        return JsonResponse({"error": "Invalid method"}, status=405)




@csrf_exempt
def get_exams_with_admin(request):
    """
    Fetch all exams and map them with admin names.
    """
    try:
        # Fetch all exams from the exam collection
        exams = exam_collection.find({}, {"_id": 1, "admin_id": 1, "superadmin_id": 1, "exam_data": 1, "updated_at": 1})

        exam_list = []

        for exam in exams:
            exam["_id"] = str(exam["_id"])  # Convert ObjectId to string
            exam["updated_at"] = exam.get("updated_at", "N/A")

            # Determine the admin ID field based on role
            admin_id_field = "admin_id" if "admin_id" in exam else "superadmin_id"
            admin_id = exam.get(admin_id_field)
            admin_name = "Unknown Admin"

            if admin_id:
                admin = admin_collection.find_one({"_id": ObjectId(admin_id)})
                if admin:
                    admin_name = admin.get("name", "Unknown Admin")

            # Extract exam details from nested structure
            exam_data = exam.get("exam_data", {})

            # Append exam details with all fields
            exam_list.append({
                "exam_id": exam["_id"],
                "admin_name": admin_name,
                "message": f"{admin_name} posted an exam",
                "exam_data": {
                    "exam_title": exam_data.get("exam_title", "No title"),
                    "about_exam": exam_data.get("about_exam", "No description"),
                    "exam_highlights": exam_data.get("exam_highlights", {}),
                    "eligibility_criteria": exam_data.get("eligibility_criteria", "N/A"),
                    "application_process": exam_data.get("application_process", "N/A"),
                    "documents_required": exam_data.get("documents_required", "N/A"),
                    "exam_centers": exam_data.get("exam_centers", "N/A"),
                    "exam_pattern": exam_data.get("exam_pattern", "N/A"),
                    "mock_test": exam_data.get("mock_test", "N/A"),
                    "admit_card": exam_data.get("admit_card", "N/A"),
                    "preparation_tips": exam_data.get("preparation_tips", "N/A"),
                    "result": exam_data.get("result", "N/A"),
                    "answer_key": exam_data.get("answer_key", "N/A"),
                    "exam_analysis": exam_data.get("exam_analysis", "N/A"),
                    "cutoff": exam_data.get("cutoff", {}),
                    "selection_process": exam_data.get("selection_process", "N/A"),
                    "question_paper": exam_data.get("question_paper", "N/A"),
                    "faq": exam_data.get("faq", "N/A"),
                    "application_deadline": exam_data.get("application_deadline", {}),
                    "syllabus": exam_data.get("syllabus", "N/A"),
                    "participating_institutes": exam_data.get("participating_institutes", "N/A"),
                    "image": exam_data.get("image", "N/A"),
                    "status": exam.get("status", "Pending"),
                    "is_publish": exam.get("is_publish", False),
                },
                "timestamp": exam["updated_at"]
            })

        return JsonResponse({"exams": exam_list}, status=200)

    except Exception as e:
        logger.error("Error fetching exams: %s", str(e))
        return JsonResponse({"error": str(e)}, status=500)

@csrf_exempt
def manage_exams(request):
    if request.method == 'GET':
        # Retrieve JWT token from Authorization Header
        auth_header = request.headers.get('Authorization')
        if not auth_header or not auth_header.startswith("Bearer "):
            return JsonResponse({'error': 'No token provided'}, status=401)

        jwt_token = auth_header.split(" ")[1]

        try:
            # Decode JWT token
            decoded_token = jwt.decode(jwt_token, JWT_SECRET, algorithms=["HS256"])
            role = decoded_token.get('role')
            admin_user = decoded_token.get('admin_user') if role == "admin" else decoded_token.get('superadmin_user')

            if not admin_user:
                return JsonResponse({"error": "Invalid token"}, status=401)

            # Fetch exams from MongoDB based on admin_user
            exams = exam_collection.find({"admin_id": admin_user} if role == "admin" else {})
            exam_list = [{**exam, "_id": str(exam["_id"])} for exam in exams]

            return JsonResponse({"exams": exam_list}, status=200)

        except jwt.ExpiredSignatureError:
            return JsonResponse({'error': 'JWT token has expired'}, status=401)
        except jwt.InvalidTokenError as e:
            return JsonResponse({'error': f'Invalid JWT token: {str(e)}'}, status=401)
        except Exception as e:
            return JsonResponse({'error': f'An error occurred: {str(e)}'}, status=400)
    else:
        return JsonResponse({'error': 'Invalid request method'}, status=405)

@csrf_exempt
def delete_exam(request, exam_id):
    """
    Delete an exam by its ID and store the deleted exam in a new collection called "deleted_exam".
    """
    if request.method == 'DELETE':
        try:
            # Check if the exam exists
            exam = exam_collection.find_one({"_id": ObjectId(exam_id)})
            if not exam:
                return JsonResponse({"error": "Exam not found"}, status=404)

            # Store the deleted exam in the "deleted_exam" collection
            deleted_exam_collection.insert_one(exam)

            # Delete the exam from the exam collection
            exam_collection.delete_one({"_id": ObjectId(exam_id)})

            return JsonResponse({"message": "Exam deleted successfully"}, status=200)
        except Exception as e:
            return JsonResponse({"error": str(e)}, status=500)
    else:
        return JsonResponse({"error": "Invalid method"}, status=405)

logger = logging.getLogger(__name__)

@csrf_exempt
def update_exam(request, exam_id):
    """
    Update an exam by its ID using POST method.
    """
    if request.method == 'POST':
        try:
            logger.info(f"Request method: {request.method}")
            logger.info(f"Request content-type: {request.content_type}")
            logger.info(f"Request POST: {request.POST}")
            logger.info(f"Request FILES: {request.FILES}")

            # Convert exam_id to ObjectId and check if the exam exists
            try:
                exam_id = ObjectId(exam_id)
            except Exception:
                return JsonResponse({"error": "Invalid exam_id format"}, status=400)

            existing_exam = exam_collection.find_one({"_id": exam_id})
            if not existing_exam:
                return JsonResponse({"error": "Exam not found"}, status=404)

            # Extract data from request
            exam_data = request.POST.get('exam_data')
            role = request.POST.get('role')
            user_id = request.POST.get('userId')

            if not exam_data:
                return JsonResponse({"error": "No 'exam_data' field in form"}, status=400)

            # Parse JSON data
            try:
                data = json.loads(exam_data)
            except json.JSONDecodeError as e:
                logger.error(f"JSON decode error: {str(e)}")
                return JsonResponse({"error": f"Invalid JSON data: {str(e)}"}, status=400)

            # Validate required fields (exam_title is required)
            exam_title = data.get('exam_title', existing_exam['exam_data'].get('exam_title'))
            if not exam_title:
                return JsonResponse({"error": "Missing required field: exam_title"}, status=400)

            # Handle Image Upload
            if 'image' in request.FILES:
                image_file = request.FILES['image']
                image_data = base64.b64encode(image_file.read()).decode('utf-8')
                data['image'] = image_data
            elif 'image' not in data and 'image' in existing_exam['exam_data']:
                data['image'] = existing_exam['exam_data']['image']  # Retain existing image
            elif 'image' in data and data['image'] is None:
                data.pop('image', None)  # Remove image if explicitly set to None

            # Transform cutoff array of objects into a dictionary (if provided)
            if 'cutoff' in data:
                cutoff_array = data.get('cutoff', existing_exam['exam_data'].get('cutoff', []))
                cutoff_dict = {}
                for item in cutoff_array:
                    if isinstance(item, dict):
                        cutoff_dict.update(item)
                data['cutoff'] = cutoff_dict
                logger.info("cutoff transformed: %s", cutoff_dict)

            # Transform exam_highlights array of objects into a dictionary (if provided)
            if 'exam_highlights' in data:
                highlights_array = data.get('exam_highlights', existing_exam['exam_data'].get('exam_highlights', []))
                highlights_dict = {}
                for item in highlights_array:
                    if isinstance(item, dict):
                        highlights_dict.update(item)
                data['exam_highlights'] = highlights_dict
                logger.info("exam_highlights transformed: %s", highlights_dict)

            # Auto-approval logic
            auto_approval_setting = superadmin_collection.find_one({"key": "auto_approval"})
            is_auto_approval = auto_approval_setting.get("value", False) if auto_approval_setting else False
            is_publish = True if role == 'superadmin' or (role == 'admin' and is_auto_approval) else None

            # Remove _id from data if present (MongoDB doesn't allow updating _id)
            if '_id' in data:
                del data['_id']

            # Handle 'edited' field if present
            edited_value = data.pop("edited", None)

            # Construct update data for MongoDB
            update_data = {"$set": {f"exam_data.{key}": value for key, value in data.items()}}
            update_data["$set"]["updated_at"] = timezone.now().isoformat()
            update_data["$set"]["admin_id" if role == "admin" else "superadmin_id"] = user_id

            # Update is_publish and status based on role and auto-approval
            if is_publish is not None:
                update_data["$set"]["is_publish"] = is_publish
                update_data["$set"]["status"] = "Published" if is_publish else "Pending"
            elif existing_exam.get('is_publish') is not None:
                update_data["$set"]["is_publish"] = existing_exam['is_publish']
                update_data["$set"]["status"] = existing_exam['status']

            # Include edited field if provided
            if edited_value is not None:
                update_data["$set"]["edited"] = edited_value

            # Log the full update data
            logger.info("Update data for MongoDB: %s", json.dumps(update_data, default=str))

            # Update the document in MongoDB
            result = exam_collection.update_one({"_id": exam_id}, update_data)

            if result.modified_count > 0:
                logger.info("Exam updated successfully with _id: %s", str(exam_id))
            else:
                logger.warning("No changes made to exam with _id: %s", str(exam_id))

            # Fetch the updated exam document to return
            updated_exam = exam_collection.find_one({"_id": exam_id})
            updated_exam["_id"] = str(updated_exam["_id"])  # Convert ObjectId to string for JSON response
            return JsonResponse({"exam": updated_exam}, status=200)

        except json.JSONDecodeError as e:
            logger.error(f"JSON decode error: {str(e)}")
            return JsonResponse({"error": f"Invalid JSON data: {str(e)}"}, status=400)
        except Exception as e:
            logger.error(f"Unexpected error: {str(e)}")
            return JsonResponse({"error": str(e)}, status=500)
    else:
        return JsonResponse({"error": "Invalid method"}, status=405)
      
@csrf_exempt
def apply_exam(request):
    try:
        data = json.loads(request.body)
        student_id = data.get("studentId")
        exam_id = data.get("examId")

        if not student_id or not exam_id:
            return JsonResponse({"error": "Student ID and Exam ID are required"}, status=400)

        # Retrieve the student document
        student = student_collection.find_one({"_id": ObjectId(student_id)})
        if not student:
            return JsonResponse({"error": "Student not found"}, status=404)

        applied_exams = student.get("applied_exams", [])
        if any(exam["exam_id"] == str(ObjectId(exam_id)) for exam in applied_exams):
            return JsonResponse({"message": "Exam already applied"}, status=200)

        # Update the student's applied exams in the database with confirmation status as null
        result = student_collection.update_one(
            {"_id": ObjectId(student_id)},
            {"$addToSet": {"applied_exams": {
                "exam_id": str(ObjectId(exam_id)),  # Convert ObjectId to string
                "confirmed": None  # Set confirmed status to null
            }}}
        )

        if result.modified_count == 0:
            return JsonResponse({"error": "Failed to update applied exams"}, status=400)

        return JsonResponse({"message": "Exam application recorded successfully"})

    except Exception as e:
        return JsonResponse({"error": str(e)}, status=400)

@csrf_exempt
def confirm_exam(request):
    try:
        data = json.loads(request.body)
        student_id = data.get("studentId")
        exam_id = data.get("examId")
        confirmed = data.get("confirmed")

        if not student_id or not exam_id or confirmed is None:
            return JsonResponse({"error": "Student ID, Exam ID, and confirmation status are required"}, status=400)

        # Update the confirmation status of the applied exam in the student collection
        result = student_collection.update_one(
            {"_id": ObjectId(student_id), "applied_exams.exam_id": exam_id},
            {"$set": {"applied_exams.$.confirmed": confirmed}}
        )

        if result.modified_count == 0:
            return JsonResponse({"error": "Failed to update confirmation status. No matching document found."}, status=400)

        # Update the exam collection to add the student ID to the applied array
        exam_result = exam_collection.update_one(
            {"_id": ObjectId(exam_id)},
            {"$addToSet": {"applied": str(ObjectId(student_id))}}  # Use $addToSet to avoid duplicates
        )

        if exam_result.modified_count == 0:
            return JsonResponse({"error": "Failed to update exam data. No matching document found."}, status=400)

        return JsonResponse({"message": "Exam application status updated successfully"})
    except Exception as e:
        return JsonResponse({"error": str(e)}, status=400)

@csrf_exempt
def get_applied_exams(request, userId):
    try:
        # Validate the user ID
        if not userId or not ObjectId.is_valid(userId):
            return JsonResponse({"error": "Invalid or missing userId"}, status=400)

        # Find the student by ID
        student = student_collection.find_one({"_id": ObjectId(userId)})

        if not student:
            return JsonResponse({"error": "Student not found"}, status=404)

        # Get the list of applied exam IDs
        applied_exams = student.get("applied_exams", [])

        # Fetch exam data for each exam ID
        exams = []
        for exam_id in applied_exams:
            if not ObjectId.is_valid(exam_id.get("exam_id")):
                continue  # Skip invalid ObjectIds

            exam = exam_collection.find_one({"_id": ObjectId(exam_id.get("exam_id"))})
            if exam:
                exam["_id"] = str(exam["_id"])
                exams.append(exam)

        return JsonResponse({"message": "Applied exams retrieved successfully", "exams": exams})

    except Exception as e:
        logger.error(f"Error fetching applied exams: {str(e)}")
        return JsonResponse({"error": str(e)}, status=400)
