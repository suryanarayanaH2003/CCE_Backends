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
from dotenv import load_dotenv
from django.core.cache import cache  # Import cache

import pytz

load_dotenv()

# Configuration
JWT_SECRET = os.environ.get("JWT_SECRET", "secret")
JWT_ALGORITHM = "HS256"
DATABASE_URL = os.environ.get(
    "MONGO_URI")
DATABASE_NAME = "CCE"
MONGODB_TIMEOUT_MS = os.environ.get("MONGODB_TIMEOUT_MS")  # 30 seconds
ADMIN_USERS_COLLECTION_NAME = "admin"
INTERNSHIP_POSTINGS_COLLECTION_NAME = "internships"
JOB_POSTINGS_COLLECTION_NAME = "jobs"
SUPERADMIN_USERS_COLLECTION_NAME = "superadmin"
REVIEWS_COLLECTION_NAME = "reviews"
DELETED_JOB_COLLECTION_NAME = 'deleted_job'
STUDENT_COLLECTION_NAME = 'student'  # Added student collection

# Logger setup
logger = logging.getLogger(__name__)

# MongoDB connection setup
client = MongoClient(DATABASE_URL,serverSelectionTimeoutMS=MONGODB_TIMEOUT_MS)
db = client[DATABASE_NAME]
admin_users_collection = db[ADMIN_USERS_COLLECTION_NAME]
internship_postings_collection = db[INTERNSHIP_POSTINGS_COLLECTION_NAME]
job_postings_collection = db[JOB_POSTINGS_COLLECTION_NAME]
superadmin_users_collection = db[SUPERADMIN_USERS_COLLECTION_NAME]
reviews_collection = db[REVIEWS_COLLECTION_NAME]
deleted_job_collection = db[DELETED_JOB_COLLECTION_NAME]
student_users_collection = db[STUDENT_COLLECTION_NAME]  # Assign student collection

# Configure Gemini API
genai.configure(api_key="AIzaSyCLDQgKnO55UQrnFsL2d79fxanIn_AL0WA")

# Configure Tesseract
pytesseract.pytesseract.tesseract_cmd = os.getenv("TESSERACT_CMD", "/usr/bin/tesseract")

def preprocess_image(image):
    """Preprocesses the image for better OCR accuracy."""
    try:
        # image = cv2.imread(image)
        gray = cv2.cvtColor(image, cv2.COLOR_BGR2GRAY)
        _, thresh = cv2.threshold(gray, 150, 255, cv2.THRESH_BINARY + cv2.THRESH_OTSU)
        return thresh
    except Exception as e:
        logger.exception("Error preprocessing image") # Log the full exception
        raise ValueError("Image preprocessing failed.  Please check the image format.")

def extract_text_from_image(image):
    """Extracts text from a PIL Image object by splitting the image into 4 parts and merging results."""
    try:
        image = cv2.cvtColor(np.array(image), cv2.COLOR_RGB2BGR)
        processed_image = preprocess_image(image)
        height, width = processed_image.shape
        parts = [
            processed_image[0:height//2, 0:width//2],
            processed_image[0:height//2, width//2:width],
            processed_image[height//2:height, 0:width//2],
            processed_image[height//2:height, width//2:width],
        ]
        
        extracted_text = [pytesseract.image_to_string(part, lang="eng").strip() for part in parts]
        final_text = "\n".join(extracted_text).strip()

        if not final_text:  # If text is empty, raise an error
            raise ValueError("Upload a correct image. No readable text detected.")

        print("Extracted Text:", extracted_text)
        return final_text


        print('text',extracted_text)
        return "\n".join(extracted_text)
    except Exception as e:
        logger.exception("Error extracting text from image")
        raise ValueError("Text extraction failed.  The image may not contain readable text.")



def analyze_text_with_gemini_api(ocr_text):
    """Processes extracted text into structured job details using the Gemini API."""
    initial_prompt = f"""
    You are an AI assistant specializing in job data extraction.
    Convert the following unstructured job posting text into a structured, well-formatted paragraph.
    The paragraph should be organized into subtopics like **Job Title, Company, Description, Responsibilities, Skills, Education, Experience, Salary, Benefits, Work Type, and Application Process**.

    **Unstructured Job Posting:**
    {ocr_text}

    **Example Output Format:**
    **Job Title:** [Extracted or 'No Data Available']
    **Company:** [Extracted or 'No Data Available']
    **Description:** [Extracted or 'No Data Available']
    **Responsibilities:**
    - Responsibility 1
    - Responsibility 2 (Infer if missing)
    **Required Skills:**
    - Skill 1
    - Skill 2 (Infer if missing)
    **Education:** [Extracted Qualification or 'No Data Available']
    **Experience:** [Years of experience required or 'No Data Available']
    **Salary:** [Extracted salary or 'No Data Available']
    **Benefits:**
    - Benefit 1
    - Benefit 2 (Infer if missing)
    **Work Type:** [Full-time/Part-time/Remote]
    **Application Process:** [Extracted Process or 'No Data Available']

    Ensure the output is well-structured and formatted properly.
    """
    model = genai.GenerativeModel("gemini-1.5-flash-8b")
    response = model.generate_content(initial_prompt)
    structured_paragraph = response.text

    main_prompt = f"""
    Extract job posting details from the following structured text and return the output in a strict JSON format.

    **Structured Job Posting:**
    {structured_paragraph}

    **Output Format (Ensure All Fields Exist & Fill Missing Ones):**
    {{
        "title": "Extracted Job Title or 'No Data Available'",
        "company_name": "Extracted Company Name or 'No Data Available'",
        "company_overview": "Extracted or 'No Data Available'",
        "company_website": "Extracted Website or 'No Data Available'",
        "job_description": "Extracted Job Description or 'No Data Available'",
        "key_responsibilities": [
            "Responsibility 1",
            "Responsibility 2",
            "Infer if missing"
        ],
        "required_skills": [
            "Skill 1",
            "Skill 2",
            "Infer if missing"
        ],
        "education_requirements": "Extracted Qualification or 'No Data Available'",
        "experience_level": "Years of experience required or 'No Data Available'",
        "salary_range": "Extracted salary or 'No Data Available'",
        "benefits": [
            "Benefit 1",
            "Benefit 2",
            "Infer if missing"
        ],
        "job_location": "Extracted location or 'No Data Available'",
        "work_type": "Full-time/Part-time (Infer from job type)",
        "application_instructions": "Extracted Application Process or 'No Data Available'",
        "application_deadline": "YYYY-MM-DD or 'No Data Available'",
        "contact_email": "Extracted email or 'No Data Available'",
        "contact_phone": ["Extracted phone number or 'No Data Available'"],
        "job_link": "Extracted job link or 'No Data Available'",
        "selectedCategory": "Job Category (Infer from job type)",
        "selectedWorkType": "On-site/Remote"
    }}

    **Ensure output is valid JSON with no additional text.**
    """
    model = genai.GenerativeModel("gemini-1.5-flash-8b")
    response = model.generate_content(main_prompt)
    try:
        cleaned_response = re.sub(r"```json|```", "", response.text).strip()
        json_output = json.loads(cleaned_response)
        required_fields = {
            "title": "No Data Available",
            "company_name": "No Data Available",
            "job_link": "No Data Available",
            "contact_email": "No Data Available",
            "contact_phone": ["No Data Available"]
        }
        for key, default_value in required_fields.items():
            if key not in json_output or not json_output[key]:
                json_output[key] = default_value
        return json_output
    except json.JSONDecodeError:
        logger.error("AI processing failed: Invalid JSON response.")
        return {"error": "AI processing failed. Please try again."}

def parse_date(date_str):
    """Parses a date string into a timezone-aware datetime object."""
    if not date_str:
        return None
    try:
        if 'T' in date_str:
            date_str = date_str.split('T')[0]
        return datetime.strptime(date_str, "%Y-%m-%d").replace(tzinfo=pytz.utc)
    except ValueError:
        logger.error("Invalid date format: %s", date_str)
        return None

def replace_nulls(d):
    """Replaces null values in a dictionary with 'N/A'."""
    for k, v in d.items():
        if isinstance(v, dict):
            replace_nulls(v)
        elif v is None:
            d[k] = 'N/A'
        elif isinstance(v, list):
            for i in range(len(v)):
                if v[i] is None:
                    v[i] = 'N/A'
    return d

def get_approval_status(job):
    """Determines the approval status of a job."""
    return "Waiting for Approval" if job.get("is_publish") is None else (
        "Approved" if job["is_publish"] else "Rejected"
    )

def get_admin_name(admin_id, superadmin_id):
    """Retrieves the admin name based on admin_id or superadmin_id from cache or DB."""
    cache_key = f"admin_name_{admin_id}_{superadmin_id}"
    admin_name = cache.get(cache_key)

    if admin_name:
        return admin_name

    try:
        if admin_id:
            admin = admin_users_collection.find_one({"_id": ObjectId(admin_id)}, {"name": 1})
            admin_name = admin.get("name", "Unknown Admin") if admin else "Unknown Admin"
        elif superadmin_id:
            superadmin = superadmin_users_collection.find_one({"_id": ObjectId(superadmin_id)}, {"name": 1})
            admin_name = superadmin.get("name", "Unknown Superadmin") if superadmin else "Unknown Superadmin"
        else:
            admin_name = "Unknown Admin"

        cache.set(cache_key, admin_name, 3600)  # Cache for 1 hour
        return admin_name
    except Exception as e:
        logger.exception("Error retrieving admin name")
        return "Unknown Admin"

def process_job_image_upload(request):
    """Processes job image uploads, extracts text using OCR, and refines it using AI."""
    if request.method == "POST":
        try:
            uploaded_image = request.FILES.get("image")
            print('uploaded_image',uploaded_image)
            if not uploaded_image:
                return json_response({"error": "No image provided"}, status=400)

            image = Image.open(uploaded_image)
            extracted_text = extract_text_from_image(image)
            job_details = analyze_text_with_gemini_api(extracted_text)

            if "error" in job_details:
                return json_response({"error": "AI processing failed. Please try again."}, status=500)

            return json_response({"message": "Text extracted successfully", "data": job_details}, status=200)

        except ValueError as ve:
            return json_response({"error": str(ve)}, status=400) #Specific error from image processing
        except Exception as e:
            logger.exception("Error processing image upload")
            return json_response({"error": "Image processing failed.  Check the image and try again."}, status=500) #General error to avoid exposing details

    return json_response({"error": "Invalid request method"}, status=405)

def create_job_posting(request):
    """Creates a new job posting in the database."""
    if request.method == 'POST':
        try:
            job_data_str = request.POST.get('job_data', '{}')
            role = request.POST.get('role')
            user_id = request.POST.get('userId')

            if not job_data_str:
                return json_response({"error": "Missing job data"}, status=400)

            try:
                data = json.loads(job_data_str)
            except json.JSONDecodeError:
                return json_response({"error": "Invalid job data format"}, status=400)

            # Update required fields to match frontend
            required_fields = [
                'title',
                'job_description',
                'company_name',
                'job_location',
                'company_website',
                'application_deadline',
                'job_link'
            ]
            
            missing_fields = [field for field in required_fields if field not in data or not data[field]]
            if missing_fields:
                return json_response({"error": f"Missing required fields: {', '.join(missing_fields)}"}, status=400)

            application_deadline_str = data.get('application_deadline')
            if not application_deadline_str:
                return json_response({"error": "Missing application deadline"}, status=400)

            application_deadline = parse_date(application_deadline_str)
            if not application_deadline:
                return json_response({"error": "Invalid deadline format. Use YYYY-MM-DD."}, status=400)

            job_posting_date = parse_date(data.get('job_posting_date'))
            interview_start_date = parse_date(data.get('interview_start_date'))
            interview_end_date = parse_date(data.get('interview_end_date'))
            expected_joining_date = parse_date(data.get('expected_joining_date'))

            now = timezone.now()
            current_status = "Active" if application_deadline >= now else "Expired"

            image = request.FILES.get('image')
            image_base64 = None
            if image:
                try:
                    image_base64 = base64.b64encode(image.read()).decode('utf-8')
                except Exception as e:
                    logger.exception("Error processing image")
                    return json_response({"error": "Error processing image"}, status=400)

            is_auto_approval = is_auto_approval_enabled()  # Using cached value
            is_publish = True if role == 'superadmin' or (role == 'admin' and is_auto_approval) else None

            job_post = {
                "job_data": {
                    "title": data.get('title'),
                    "job_description": data.get('job_description', ""),
                    "experience_level": data.get('experience_level', ""),
                    "industry_type": data.get('industry_type', ""),
                    "work_type": data.get('work_type', ""),
                    "company_name": data.get('company_name'),
                    "company_website": data.get('company_website', ""),
                    "job_location": data.get('job_location', ""),
                    "salary_range": data.get('salary_range', ""),
                    "education_requirements": data.get('education_requirements', ""),
                    "work_experience_requirement": data.get('work_experience_requirement', ""),
                    "professional_certifications": data.get('professional_certifications', ""),
                    "minimum_marks_requirement": data.get('minimum_marks_requirement', ""),
                    "technical_skills": data.get('technical_skills', []),
                    "soft_skills": data.get('soft_skills', []),
                    "age_limit": data.get('age_limit', ""),
                    "documents_required": data.get('documents_required', ""),
                    "additional_skills": data.get('additional_skills', []),
                    "job_posting_date": data.get('job_posting_date'),
                    "application_deadline": data.get('application_deadline'),
                    "interview_start_date": data.get('interview_start_date'),
                    "interview_end_date": data.get('interview_end_date'),
                    "job_link": data.get('job_link'),
                    "selection_process": data.get('selection_process', ""),
                    "steps_to_apply": data.get('steps_to_apply', ""),
                    "relocation_assistance": data.get('relocation_assistance', ""),
                    "remote_work_availability": data.get('remote_work_availability', ""),
                    "expected_joining_date": data.get('expected_joining_date'),
                    "work_schedule": data.get('work_schedule', ""),
                    "key_responsibilities": data.get('key_responsibilities', []),
                    "preparation_tips": data.get('preparation_tips', ""),
                    "image": image_base64
                },
                f"{role}_id": user_id,
                "is_publish": is_publish,
                "status": current_status,
                "updated_at": timezone.now().isoformat()
            }

            try:
                job_postings_collection.insert_one(job_post)
                return json_response({"message": "Job posted successfully, awaiting approval."}, status=200)
            except Exception as db_err:
                logger.exception("Database insertion error")
                return json_response({"error": "Failed to save job posting. Please try again."}, status=500)  # General DB error

        except Exception as e:
            logger.exception("Error creating job posting")
            return json_response({"error": "Failed to create job posting.  Check the data and try again."}, status=500)  # General error

    return json_response({"error": "Invalid request method"}, status=405)

def is_auto_approval_enabled():
    """Retrieves auto-approval setting from cache or DB."""
    auto_approval = cache.get("auto_approval")

    if auto_approval is None:
        try:
            setting = superadmin_users_collection.find_one({"key": "auto_approval"}, limit=1) #Limit to one document
            auto_approval = setting.get("value", False) if setting else False
            cache.set("auto_approval", auto_approval, 3600)  # Cache for 1 hour
        except Exception as e:
            logger.exception("Error retrieving auto-approval setting")
            return False  # Default to False if there's an error

    return auto_approval

def retrieve_jobs_for_email_notifications():
    """Retrieves job details for email notifications, including approval status and admin info."""
    try:
        jobs = job_postings_collection.find().limit(100) # Limit to 100 jobs to prevent large queries
        job_list = []

        for job in jobs:
            job["_id"] = str(job["_id"])
            approval_status = get_approval_status(job)
            admin_id = job.get("admin_id")
            admin_name = "Super Admin"
            if admin_id:
                admin = admin_users_collection.find_one({"_id": ObjectId(admin_id)}, {"name": 1})
                if admin:
                    admin_name = admin.get("name", "Super Admin")

            if "job_data" in job and "application_deadline" in job["job_data"]:
                deadline = job["job_data"]["application_deadline"]
                if deadline:
                    formatted_deadline = deadline.strftime("%Y-%m-%d") if isinstance(deadline, datetime) else deadline
                    job["job_data"]["application_deadline"] = formatted_deadline

            job["approval_status"] = approval_status
            job["admin_name"] = admin_name
            job_list.append(job)

        return job_list

    except Exception as e:
        logger.exception("Error retrieving jobs for email notifications")
        raise Exception("Failed to retrieve job data for notifications.")
    
def update_job_posting(request, job_id):
    """
    Updates a job posting with the provided data.

    Args:
        request: The HTTP request object.
        job_id: The ID of the job posting to update.

    Returns:
        JsonResponse: A JSON response indicating the success or failure of the update.
    """
    if request.method == 'POST':
        try:
            job_data_str = request.POST.get('job_data', '{}')
            data = json.loads(job_data_str)

            # Handle image file (only applicable for multipart/form-data requests)
            image = request.FILES.get('image')
            image_base64 = None
            if image:
                try:
                    image_base64 = base64.b64encode(image.read()).decode('utf-8')
                except Exception as e:
                    logger.error("Error processing image: %s", str(e))
                    return JsonResponse({"error": "Error processing image file"}, status=400)

            # Ensure only the provided fields are updated (avoiding data appending issues)
            update_fields = {
                "job_data.title": data.get("title"),
                "job_data.job_description": data.get("job_description"),
                "job_data.experience_level": data.get("experience_level"),
                "job_data.industry_type": data.get("industry_type", ""),
                "job_data.work_type": data.get("work_type"),
                "job_data.company_name": data.get("company_name"),
                "job_data.company_website": data.get("company_website"),
                "job_data.job_location": data.get("job_location"),
                "job_data.salary_range": data.get("salary_range"),
                "job_data.education_requirements": data.get("education_requirements"),
                "job_data.work_experience_requirement": data.get("work_experience_requirement"),
                "job_data.professional_certifications": data.get("professional_certifications"),
                "job_data.minimum_marks_requirement": data.get("minimum_marks_requirement"),
                "job_data.technical_skills": data.get("technical_skills", []),
                "job_data.soft_skills": data.get("soft_skills", []),
                "job_data.age_limit": data.get("age_limit", ""),
                "job_data.documents_required": data.get("documents_required"),
                "job_data.additional_skills": data.get("additional_skills", []),
                "job_data.job_posting_date": data.get("job_posting_date"),
                "job_data.application_deadline": data.get("application_deadline"),
                "job_data.interview_start_date": data.get("interview_start_date"),
                "job_data.interview_end_date": data.get("interview_end_date"),
                "job_data.job_link": data.get("job_link"),
                "job_data.selection_process": data.get("selection_process", ""),
                "job_data.steps_to_apply": data.get("steps_to_apply", ""),
                "job_data.relocation_assistance": data.get("relocation_assistance"),
                "job_data.remote_work_availability": data.get("remote_work_availability"),
                "job_data.expected_joining_date": data.get("expected_joining_date"),
                "job_data.work_schedule": data.get("work_schedule"),
                "job_data.key_responsibilities": data.get("key_responsibilities", []),
                "job_data.preparation_tips": data.get("preparation_tips"),
                "job_data.image": image_base64,
            }

            # Use `$set` to update only specified fields
            result = job_postings_collection.update_one(
                {"_id": ObjectId(job_id)},
                {"$set": update_fields}
            )

            if result.matched_count == 0:
                return JsonResponse({"error": "Job post not found"}, status=404)

            return JsonResponse({"message": "Job post updated successfully"}, status=200)

        except Exception as e:
            logger.error("Error: %s", str(e))
            return JsonResponse({"error": str(e)}, status=500)

    return JsonResponse({"error": "Invalid request method. Only POST is allowed."}, status=405)

def delete_job_posting(job_id):
    """
    Deletes a job by its ID, stores it in a separate collection, and updates student records.

    Args:
        job_id: The ID of the job posting to delete.

    Returns:
        JsonResponse: A JSON response indicating the success or failure of the deletion.
    """
    try:
        try:
            job = job_postings_collection.find_one({"_id": ObjectId(job_id)})
            if not job:
                return json_response({"error": "Job not found"}, status=404)
        except InvalidId:
            return json_response({"error": "Invalid job ID format"}, status=400)

        try:
            deleted_job_collection.insert_one(job)
            job_postings_collection.delete_one({"_id": ObjectId(job_id)})

            student_users_collection.update_many({"saved_jobs": job_id}, {"$pull": {"saved_jobs": job_id}})
            student_users_collection.update_many({"applied_jobs.job_id": job_id}, {"$pull": {"applied_jobs": {"job_id": job_id}}})

            return json_response({"message": "Job deleted successfully"}, status=200)
        except Exception as db_err:
            logger.exception("Database deletion error")
            return json_response({"error": "Failed to delete job. Please try again."}, status=500)
    except Exception as e:
        logger.exception("Error deleting job posting")
        return json_response({"error": "Failed to delete job. Please try again."}, status=500)

def get_job_posting_details(job_id):
    """
    Retrieves a specific job by its ID.

    Args:
        job_id: The ID of the job posting to retrieve.

    Returns:
        JsonResponse: A JSON response containing the job details or an error message.
    """
    try:
        try:
            job = job_postings_collection.find_one({"_id": ObjectId(job_id)})
            if not job:
                return json_response({"error": "Job not found"}, status=404)
        except InvalidId:
            return json_response({"error": "Invalid job ID format"}, status=400)

        job["_id"] = str(job["_id"])
        return job
    except Exception as e:
        logger.exception("Error retrieving job posting details")
        return json_response({"error": "Failed to retrieve job details."}, status=500)

def retrieve_published_jobs():
    """
    Retrieves all published jobs.

    Returns:
        JsonResponse: A JSON response containing the list of published jobs or an error message.
    """
    try:
        job_list = []
        published_jobs = job_postings_collection.find({"is_publish": True}).limit(50) # Limit results for performance
        for job in published_jobs:
            job["_id"] = str(job["_id"])
            if "job_data" in job and "job_location" in job["job_data"]:
                job["job_data"]["location"] = job["job_data"].pop("job_location")

            if "job_data" in job:
                excluded_fields = [
                    "technical_skills", "soft_skills", "selection_process", "work_experience_requirement",
                    "professional_certifications", "minimum_marks_requirement", "additional_skills",
                    "key_responsibilities", "work_schedule",
                ]
                for field in excluded_fields:
                    job["job_data"].pop(field, None)

            total_views = len(job.get("views", []))
            job.pop("views", None)
            job["views"] = total_views
            job_list.append(job)
        return job_list
    except Exception as e:
        logger.exception("Error retrieving published jobs")
        return [] #Return empty list or raise exception

def review_job_posting(request, job_id):
    """
    Approves or rejects a job posting.

    Args:
        request: The HTTP request object.
        job_id: The ID of the job posting to review.

    Returns:
        JsonResponse: A JSON response indicating the success or failure of the review.
    """
    if request.method == "POST":
        try:
            data = json.loads(request.body)
            action = data.get("action")
            if action not in ["approve", "reject"]:
                return json_response({"error": "Invalid action"}, status=400)

            try:
                job = job_postings_collection.find_one({"_id": ObjectId(job_id)})
                if not job:
                    return json_response({"error": "Job not found"}, status=404)
            except InvalidId:
                return json_response({"error": "Invalid job ID format"}, status=400)

            if action == "approve":
                job_postings_collection.update_one(
                    {"_id": ObjectId(job_id)},
                    {"$set": {"is_publish": True, "updated_at": datetime.now()}}
                )
                return json_response({"message": "Job approved and published successfully"}, status=200)
            elif action == "reject":
                job_postings_collection.update_one(
                    {"_id": ObjectId(job_id)},
                    {"$set": {"is_publish": False, "updated_at": datetime.now()}}
                )
                return json_response({"message": "Job rejected successfully"}, status=200)
        except json.JSONDecodeError:
            return json_response({"error": "Invalid data format"}, status=400)
        except Exception as e:
            logger.exception("Error reviewing job posting")
            return json_response({"error": "Failed to review job posting."}, status=500)
    else:
        return json_response({"error": "Invalid request method"}, status=405)

def manage_jobs_by_admin_user(request):
    """
    Retrieves jobs based on the admin user's ID.

    Args:
        request: The HTTP request object.

    Returns:
        JsonResponse: A JSON response containing the list of jobs managed by the admin user.
    """
    if request.method == 'GET':
        auth_header = request.headers.get('Authorization')
        if not auth_header or not auth_header.startswith("Bearer "):
            return json_response({'error': 'Authentication required'}, status=401)

        jwt_token = auth_header.split(" ")[1]

        try:
            decoded_token = jwt.decode(jwt_token, JWT_SECRET, algorithms=["HS256"])
            role = decoded_token.get('role')
            admin_user = decoded_token.get('admin_user') if role == "admin" else decoded_token.get('superadmin_user')

            if not admin_user:
                return json_response({"error": "Invalid token"}, status=401)

            query = {"admin_id": admin_user} if role == "admin" else {}
            
            jobs = job_postings_collection.find(query).limit(50)  # Limit results for performance

            # Exclude the image field from the response
            job_list = []
            for job in jobs:
                job_dict = {**job, "_id": str(job["_id"]), "views": len(job.get("views", []))}
                job_dict.pop("image", None)  # Remove the 'image' field if it exists
                job_list.append(job_dict)

            return json_response({"jobs": job_list}, status=200)

        except jwt.ExpiredSignatureError:
            return json_response({'error': 'Token expired'}, status=401)
        except jwt.InvalidTokenError:
            return json_response({'error': 'Invalid token'}, status=401)
        except Exception as e:
            logger.exception("Error managing jobs by admin user")
            return json_response({'error': 'Failed to retrieve jobs.'}, status=500)
    else:
        return json_response({'error': 'Invalid request method'}, status=405)


def retrieve_jobs_with_admin_info():
    """
    Retrieves all jobs and maps them with admin names.

    Returns:
        JsonResponse: A JSON response containing the list of jobs with admin information.
    """
    try:
        jobs = job_postings_collection.find({}, {"_id": 1, "admin_id": 1, "superadmin_id": 1, "job_data": 1, "updated_at": 1}).limit(50) # Limit results for performance
        job_list = []

        for job in jobs:
            job["_id"] = str(job["_id"])
            job["updated_at"] = job.get("updated_at", "N/A")
            admin_name = get_admin_name(job.get("admin_id"), job.get("superadmin_id"))
            job_list.append({
                "job_id": job["_id"],
                "admin_name": admin_name,
                "message": f"{admin_name} posted a job",
                "job_data": job.get("job_data", {}),
                "timestamp": job["updated_at"]
            })

        return job_list

    except Exception as e:
        logger.exception("Error retrieving jobs with admin info")
        return [] # Return empty list or raise exception
def json_response(data, status=200):
    """Helper function to create a JSON response."""
    return JsonResponse(data, status=status)

def json_response(data, status=200):
    """Helper function to create a JSON response."""
    return JsonResponse(data, status=status)

def extract_jwt_payload(request):
    """Helper function to extract and decode JWT token from the request."""
    auth_header = request.headers.get('Authorization')
    if not auth_header or not auth_header.startswith("Bearer "):
        return None

    jwt_token = auth_header.split(" ")[1]

    try:
        return jwt.decode(jwt_token, JWT_SECRET, algorithms=["HS256"])
    except jwt.ExpiredSignatureError:
        raise AuthenticationFailed('JWT token has expired')
    except jwt.InvalidTokenError:
        raise AuthenticationFailed('Invalid JWT token')

def extract_jwt_payload(request):
    """
    Helper function to extract and decode JWT token from the request.

    Args:
        request: The HTTP request object.

    Returns:
        dict: The decoded JWT payload.

    Raises:
        AuthenticationFailed: If the token is missing, invalid, or expired.
    """
    auth_header = request.headers.get('Authorization')
    if not auth_header or not auth_header.startswith("Bearer "):
        return None

    jwt_token = auth_header.split(" ")[1]

    try:
        return jwt.decode(jwt_token, JWT_SECRET, algorithms=["HS256"])
    except jwt.ExpiredSignatureError:
        raise AuthenticationFailed('JWT token has expired')
    except jwt.InvalidTokenError:
        raise AuthenticationFailed('Invalid JWT token')

@csrf_exempt
def upload_job_image_view(request):
    """View function to handle job image uploads."""
    return process_job_image_upload(request)

@csrf_exempt
def job_post_view(request):
    """View function to handle job posting creation."""
    return create_job_posting(request)

@csrf_exempt
def get_jobs_for_mail_view(request):
    """View function to retrieve jobs for email notifications."""
    try:
        jobs = retrieve_jobs_for_email_notifications()
        return json_response({"jobs": jobs}, status=200)
    except Exception as e:
        logger.error("Error in get_jobs_for_mail_view: %s", str(e))
        return json_response({"error": str(e)}, status=500)

@csrf_exempt
def update_job_view(request, job_id):
    """View function to handle job posting updates."""
    return update_job_posting(request, job_id)

@csrf_exempt
def delete_job_view(request, job_id):
    """View function to handle job posting deletion."""
    if request.method == 'DELETE':
        return delete_job_posting(job_id)
    else:
        return json_response({"error": "Invalid method"}, status=405)

@csrf_exempt
def get_job_by_id_view(request, job_id):
    """View function to retrieve a job posting by ID."""
    try:
        job = get_job_posting_details(job_id)
        return json_response({"job": job}, status=200)
    except Exception as e:
        logger.error("Error in get_job_by_id_view: %s", str(e))
        return json_response({"error": str(e)}, status=500)

@csrf_exempt
def get_published_jobs_view(request):
    """View function to retrieve all published job postings."""
    try:
        jobs = retrieve_published_jobs()
        return json_response({"jobs": jobs}, status=200)
    except Exception as e:
        logger.error("Error in get_published_jobs_view: %s", str(e))
        return json_response({"error": str(e)}, status=500)

@csrf_exempt
def review_job_view(request, job_id):
    """View function to handle job posting review (approval/rejection)."""
    return review_job_posting(request, job_id)

@csrf_exempt
def manage_jobs_view(request):
    """View function to manage jobs by admin user."""
    return manage_jobs_by_admin_user(request)

@csrf_exempt
def get_jobs_with_admin_view(request):
    """View function to retrieve jobs with admin information."""
    try:
        jobs = retrieve_jobs_with_admin_info()
        return json_response({"jobs": jobs}, status=200)
    except Exception as e:
        logger.error("Error in get_jobs_with_admin_view: %s", str(e))
        return json_response({"error": str(e)}, status=500)