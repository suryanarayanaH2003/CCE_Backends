import json
import base64
import re
import logging
import threading
import queue
import time
import functools
from io import BytesIO
from datetime import datetime

import jwt
import pytz
import requests
import os
from bson import ObjectId
from bson.errors import InvalidId

from django.http import JsonResponse, HttpResponse
from django.views.decorators.csrf import csrf_exempt
from django.utils import timezone
from pymongo import MongoClient
from django.conf import settings


# Configuration
JWT_SECRET = os.environ.get("JWT_SECRET", "secret")
JWT_ALGORITHM = "HS256"
DATABASE_URL = os.environ.get(
    "MONGO_URI")
DATABASE_NAME = "CCE"
MONGODB_TIMEOUT_MS = os.environ.get("MONGODB_TIMEOUT_MS")
client = MongoClient(DATABASE_URL,serverSelectionTimeoutMS=MONGODB_TIMEOUT_MS)
db = client[DATABASE_NAME]

EXAM_COLLECTION_NAME = "exam"
SUPERADMIN_COLLECTION_NAME = "superadmin"
ADMIN_COLLECTION_NAME = "admin"
DELETED_EXAM_COLLECTION_NAME = "deleted_exam"
STUDENT_COLLECTION_NAME = "students"

admin_collection = db[ADMIN_COLLECTION_NAME]
superadmin_collection = db[SUPERADMIN_COLLECTION_NAME]
exam_collection = db[EXAM_COLLECTION_NAME]
deleted_exam_collection = db[DELETED_EXAM_COLLECTION_NAME]
student_collection = db[STUDENT_COLLECTION_NAME]

# Logger setup
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

# Configure logger for async tasks
async_logger = logging.getLogger('async_exam')
async_logger.setLevel(logging.INFO)

# Task management system
task_queue = queue.Queue()
task_results = {}
task_status = {}

def generate_task_id():
    """Generate a unique task ID for background processing.
    
    Returns:
        str: A unique identifier for a task.
    """
    return f"task_{int(time.time() * 1000)}_{hash(str(time.time()))}"

def background_worker():
    """Background worker to process tasks asynchronously.
    
    This function runs in a separate thread and processes tasks from the queue.
    It handles task execution, error handling, and resource cleanup.
    """
    while True:
        try:
            task_id, func, args, kwargs = task_queue.get()
            if task_id is None:  # Shutdown signal
                break
                
            # Update task status
            task_status[task_id] = "processing"
            async_logger.info(f"Processing task {task_id}: {func.__name__}")
            
            try:
                # Execute the task
                result = func(*args, **kwargs)
                task_results[task_id] = {"success": True, "data": result}
                task_status[task_id] = "completed"
                async_logger.info(f"Task {task_id} completed successfully")
            except Exception as e:
                # Handle errors
                task_results[task_id] = {"success": False, "error": str(e)}
                task_status[task_id] = "failed"
                async_logger.error(f"Task {task_id} failed: {str(e)}")
                
            # Clean up old tasks (keep last 100)
            if len(task_results) > 100:
                oldest_keys = sorted(task_results.keys())[:len(task_results) - 100]
                for key in oldest_keys:
                    task_results.pop(key, None)
                    task_status.pop(key, None)
                    
        except Exception as e:
            async_logger.error(f"Error in background worker: {str(e)}")
        finally:
            task_queue.task_done()

# Start background worker thread
worker_thread = threading.Thread(target=background_worker, daemon=True)
worker_thread.start()

def async_task(func):
    """Decorator to run a function asynchronously.
    
    This decorator allows any function to be executed in a background thread
    by adding it to the task queue.
    
    Args:
        func (callable): The function to run asynchronously.
        
    Returns:
        function: A wrapper function that adds the task to the queue.
    """
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        task_id = generate_task_id()
        task_status[task_id] = "pending"
        task_queue.put((task_id, func, args, kwargs))
        return task_id
    return wrapper

# Async versions of heavy operations
@async_task
def create_exam_post_async(data, role, user_id, image_base64=None):
    """Create an exam post asynchronously.

    Args:
        data (dict): The exam data.
        role (str): The user role (admin/superadmin).
        user_id (str): The user ID.
        image_base64 (str, optional): Base64 encoded image data.

    Returns:
        dict: Result of the operation including success status and message.
    """
    try:
        # Auto-approval logic
        auto_approval_setting = superadmin_collection.find_one({"key": "auto_approval"})
        is_auto_approval = auto_approval_setting.get("value", False) if auto_approval_setting else False
        is_publish = True if role == 'superadmin' or (role == 'admin' and is_auto_approval) else None

        # Extract and validate application_deadline
        application_deadline_str = data.get('application_deadline')
        if not application_deadline_str:
            return {"error": "Missing required field: application_deadline"}

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
            return {"error": "Invalid date format for application_deadline. Use YYYY-MM-DD."}

        # Check current status based on deadline
        now = timezone.now()
        current_status = "Active" if application_deadline >= now else "Expired"

        # Transform cutoff array of objects into a dictionary
        cutoff_array = data.get('cutoff', [])
        cutoff_dict = {}
        for item in cutoff_array:
            if isinstance(item, dict):
                cutoff_dict.update(item)  # Merge each object's key-value pair

        # Transform exam_highlights array of objects into a dictionary
        highlights_array = data.get('exam_highlights', [])
        highlights_dict = {}
        for item in highlights_array:
            if isinstance(item, dict):
                highlights_dict.update(item)  # Merge each object's key-value pair

        # Construct exam post document with all fields
        exam_post = {
            "exam_data": {
                "exam_title": data['exam_title'],
                "exam_link": data.get('exam_link', ""),
                "about_exam": data.get('about_exam', ""),
                "exam_highlights": highlights_dict,
                "eligibility_criteria": data.get('eligibility_criteria', ""),
                "application_process": data.get('application_process', ""),
                "documents_required": data.get('documents_required', ""),
                "exam_centers": data.get('exam_centers', ""),
                "exam_pattern": data.get('exam_pattern', ""),
                "organization" : data.get('organization', ""),  
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
            "status": "Pending" if is_publish is None else current_status,
            "updated_at": timezone.now().isoformat()
        }

        # Insert into MongoDB exam_collection
        result = exam_collection.insert_one(exam_post)

        return {
            "message": "Exam posted successfully, awaiting approval if posted by admin.",
            "exam_id": str(result.inserted_id)
        }

    except Exception as e:
        async_logger.error(f"Error creating exam: {str(e)}")
        raise

@csrf_exempt
def exam_post(request):
    """Posts a new exam to the database.
    
    Supports both synchronous and asynchronous processing modes. When async=true is passed
    as a parameter, the exam creation happens in the background and a task ID is returned.

    Args:
        request (HttpRequest): The HTTP request object containing exam data.

    Returns:
        JsonResponse: A JSON response indicating success/failure or task ID if async.
    """
    if request.method != 'POST':
        return JsonResponse(
            {"error": "Invalid request method. Only POST is allowed."}, status=405)
    
    try:
        # Parse request data
        exam_data = request.POST.get('exam_data')
        role = request.POST.get('role')
        user_id = request.POST.get('userId')

        if not exam_data:
            return JsonResponse({"error": "Missing exam_data field in request"}, status=400)

        try:
            data = json.loads(exam_data)
        except json.JSONDecodeError:
            return JsonResponse({"error": "Invalid JSON format in exam_data"}, status=400)

        # Validate required fields
        required_fields = ['exam_title', 'exam_link', 'application_deadline']
        missing_fields = [field for field in required_fields if field not in data or not data[field]]
        if missing_fields:
            return JsonResponse({"error": f"Missing required fields: {', '.join(missing_fields)}"}, status=400)

        # Handle optional image upload if included
        image = request.FILES.get('image')
        image_base64 = None
        if image:
            try:
                image_base64 = base64.b64encode(image.read()).decode('utf-8')
            except Exception as e:
                logger.error("Error processing image: %s", str(e))
                return JsonResponse({"error": "Error processing image file"}, status=400)
        
        # Check if async processing is requested
        use_async = request.POST.get('async', '').lower() == 'true'
        
        if use_async:
            # Process asynchronously
            task_id = create_exam_post_async(data, role, user_id, image_base64)
            
            # Return task information
            return JsonResponse({
                "message": "Exam submission started",
                "task_id": task_id,
                "status_url": f"/api/exam/task/{task_id}/status/"
            }, status=202)  # 202 Accepted
        else:
            # Auto-approval logic
            auto_approval_setting = superadmin_collection.find_one({"key": "auto_approval"})
            is_auto_approval = auto_approval_setting.get("value", False) if auto_approval_setting else False
            is_publish = True if role == 'superadmin' or (role == 'admin' and is_auto_approval) else None

            # Extract and validate application_deadline
            application_deadline_str = data.get('application_deadline')
            if not application_deadline_str:
                return JsonResponse({"error": "Missing required field: application_deadline"}, status=400)

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

            # Check current status based on deadline
            now = timezone.now()
            current_status = "Active" if application_deadline >= now else "Expired"

            # Transform cutoff array of objects into a dictionary
            cutoff_array = data.get('cutoff', [])
            cutoff_dict = {}
            for item in cutoff_array:
                if isinstance(item, dict):
                    cutoff_dict.update(item)  # Merge each object's key-value pair

            # Transform exam_highlights array of objects into a dictionary
            highlights_array = data.get('exam_highlights', [])
            highlights_dict = {}
            for item in highlights_array:
                if isinstance(item, dict):
                    highlights_dict.update(item)  # Merge each object's key-value pair

            # Construct exam post document with all fields
            exam_post = {
                "exam_data": {
                    "exam_title": data['exam_title'],
                    "exam_link": data.get('exam_link', ""),
                    "about_exam": data.get('about_exam', ""),
                    "exam_highlights": highlights_dict,
                    "eligibility_criteria": data.get('eligibility_criteria', ""),
                    "application_process": data.get('application_process', ""),
                    "documents_required": data.get('documents_required', ""),
                    "exam_centers": data.get('exam_centers', ""),
                    "exam_pattern": data.get('exam_pattern', ""),
                    "organization" : data.get('organization', ""),
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

            # Insert into MongoDB exam_collection
            exam_collection.insert_one(exam_post)

            return JsonResponse({"message": "Exam posted successfully, awaiting approval if posted by admin."}, status=200)

    except Exception as e:
        return JsonResponse({"error": str(e)}, status=500)


@csrf_exempt
def check_task_status(request, task_id):
    """Check the status of an asynchronous task.
    
    Allows clients to poll for task completion and retrieve results.
    
    Args:
        request (HttpRequest): The HTTP request.
        task_id (str): The ID of the task to check.
        
    Returns:
        JsonResponse: A JSON response containing task status and result if completed.
    """
    try:
        # Get task status
        status = task_status.get(task_id)
        if not status:
            return JsonResponse({"error": "Task not found"}, status=404)
            
        # Return appropriate response based on status
        if status == "pending" or status == "processing":
            return JsonResponse({
                "status": status,
                "message": "Task is in progress"
            })
        elif status == "completed":
            result = task_results.get(task_id, {})
            return JsonResponse({
                "status": "completed",
                "data": result.get("data", {})
            })
        elif status == "failed":
            result = task_results.get(task_id, {})
            return JsonResponse({
                "status": "failed",
                "error": result.get("error", "Unknown error")
            })
        else:
            return JsonResponse({
                "status": status,
                "message": "Unknown task status"
            })
    except Exception as e:
        return JsonResponse({"error": str(e)}, status=500)

@csrf_exempt
def get_published_exams(request):
    """Retrieves all published exams.

    Args:
        request (HttpRequest): The HTTP request object.

    Returns:
        JsonResponse: A JSON response containing a list of published exams or an error message.
    """
    try:
        # Find all published exams
        exams = exam_collection.find({"is_publish": True,})
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

        return JsonResponse({"exams": exam_list}, status=200)

    except Exception as e:
        logger.error("Error fetching published exams: %s", str(e))
        return JsonResponse({"error": str(e)}, status=500)
  
@csrf_exempt
def save_exam(request, pk):
    if request.method == "POST":
        try:
            data = json.loads(request.body)
            user_id = data.get("userId")
            if not user_id:
                return JsonResponse(
                    {"error": "User ID is required"}, status=400
                )

            student_collection.update_one(
                {"_id": ObjectId(user_id)},
                {"$addToSet": {"saved_exam": pk}},
            )

            return JsonResponse({"message": "Exam saved successfully"})
        except Exception as e:
            return JsonResponse({"error": str(e)}, status=400)


@csrf_exempt
def unsave_exam(request, pk):
    if request.method == "POST":
        try:
            data = json.loads(request.body)
            user_id = data.get("userId")

            if not user_id:
                return JsonResponse(
                    {"error": "User ID is required"}, status=400
                )

            student_collection.update_one(
                {"_id": ObjectId(user_id)}, {"$pull": {"saved_exam": pk}}
            )

            return JsonResponse({"message": "Exam removed from saved"})
        except Exception as e:
            return JsonResponse({"error": str(e)}, status=400)
        
@csrf_exempt
def get_saved_exams(request, user_id):
    try:
        
        if not user_id or not ObjectId.is_valid(user_id):
            return JsonResponse(
                {"error": "Invalid or missing user_id"}, status=400
            )

        user = student_collection.find_one({"_id": ObjectId(user_id)})

        if not user:
            return JsonResponse(
                {"error": "User not found"}, status=404
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
        return JsonResponse({"error": str(e)}, status=400)
    
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

        return JsonResponse({"exams": exam_list}, status=200)

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
            elif existing_exam.get('is_publish') is not None:
                update_data["$set"]["is_publish"] = existing_exam['is_publish']

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
