from .admin_views import *
from .views import *
import threading
import queue
import time
import functools
from io import BytesIO
import logging

# Configuration
JWT_SECRET = os.environ.get("JWT_SECRET", "secret")
JWT_ALGORITHM = "HS256"

INTERNSHIP_COLLECTION_NAME = "internships"
internship_collection = db[INTERNSHIP_COLLECTION_NAME]
DELETED_INTERNSHIP_COLLECTION_NAME = 'deleted_internship'
deleted_internship_collection = db[DELETED_INTERNSHIP_COLLECTION_NAME]
# Configure logger for async tasks
async_logger = logging.getLogger('async_internship')
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
def process_internship_image_async(image_data):
    """Process internship image asynchronously to extract text via OCR.
    
    Args:
        image_data: The image data to process.
        
    Returns:
        dict: Structured internship data extracted from the image.
    """
    try:
        # Process image
        image = Image.open(image_data)
        extracted_text = pytesseract.image_to_string(image, lang="eng")
        
        # Parse the extracted text
        internship_data = parse_internship_details(extracted_text)
        return internship_data
    except Exception as e:
        async_logger.error(f"Error processing image: {str(e)}")
        raise

@async_task
def create_internship_post_async(data, role, userid, image_base64=None):
    """Create an internship post asynchronously.
    
    Args:
        data (dict): The internship data.
        role (str): The user role (admin/superadmin).
        userid (str): The user ID.
        image_base64 (str, optional): Base64 encoded image data.
        
    Returns:
        dict: Result of the operation including success status and message.
    """
    try:
        # Get auto approval setting
        auto_approval_setting = superadmin_collection.find_one({"key": "auto_approval"})
        is_auto_approval = auto_approval_setting.get("value", False) if auto_approval_setting else False

        # Determine publication status based on role
        is_publish = None
        if role == 'admin' and is_auto_approval:
            is_publish = True
        elif role == 'superadmin':
            is_publish = True

        # Validate application deadline format
        application_deadline_str = data.get('application_deadline')
        try:
            application_deadline = datetime.strptime(
                application_deadline_str, "%Y-%m-%d").replace(tzinfo=pytz.utc)
        except ValueError:
            return {"error": "Invalid date format for application_deadline. Use YYYY-MM-DD."}

        # Determine internship status based on deadline
        now = timezone.now()
        current_status = "Active" if application_deadline >= now else "Expired"

        # Create internship document
        internship_post = {
            "internship_data": {
                "title": data['title'],
                "company_name": data['company_name'],
                "location": data['location'],
                "industry_type": data.get('industry_type', "NA"),
                "duration": data['duration'],
                "stipend": data['stipend'],
                "application_deadline": application_deadline,
                "required_skills": data['skills_required'],
                "technical_skills": data.get('technical_skills', []),
                "soft_skills": data.get('soft_skills', []),
                "additional_skills": data.get('additional_skills', []),
                "education_requirements": data.get('education_requirements', "NA"),
                "job_description": data['job_description'],
                "company_website": data['company_website'],
                "internship_type": data['internship_type'],
                "documents_required": data.get('documents_required', "NA"),
                "internship_posting_date": data.get('internship_posting_date', "NA"),
                "interview_start_date": data.get('interview_start_date', "NA"),
                "interview_end_date": data.get('interview_end_date', "NA"),
                "internship_link": data.get('internship_link', "NA"),
                "selection_process": data.get('selection_process', "NA"),
                "steps_to_apply": data.get('steps_to_apply', "NA"),
                "image": image_base64
            },
            "admin_id" if role == "admin" else "superadmin_id": userid,
            "is_publish": is_publish,
            "status": current_status,
            "updated_at": timezone.now().isoformat()
        }

        # Insert into database
        result = internship_collection.insert_one(internship_post)
        
        return {
            "message": "Internship posted successfully, awaiting approval.",
            "internship_id": str(result.inserted_id)
        }
    except Exception as e:
        async_logger.error(f"Error creating internship: {str(e)}")
        raise

@csrf_exempt
def upload_internship_image(request):
    """Handles internship image uploads, extracts text using OCR, and refines it using AI.
    
    Supports both synchronous and asynchronous processing modes. When async=true is passed
    as a parameter, the image processing happens in the background and a task ID is returned.
    
    Args:
        request (HttpRequest): The HTTP request containing the image file.
        
    Returns:
        JsonResponse: A JSON response containing extracted internship data or task ID.
    """
    if request.method != "POST":
        return JsonResponse({"error": "Invalid request method"}, status=405)
    
    try:
        # Get uploaded image
        internship_image = request.FILES.get("image")
        if not internship_image:
            return JsonResponse({"error": "No image provided"}, status=400)

        # Check if async processing is requested
        use_async = request.POST.get('async', '').lower() == 'true'
        
        if use_async:
            # Process asynchronously
            task_id = process_internship_image_async(internship_image)
            
            # Return task information
            return JsonResponse({
                "message": "Image processing started",
                "task_id": task_id,
                "status_url": f"/api/internship/task/{task_id}/status/"
            }, status=202)  # 202 Accepted
        else:
            # Original synchronous behavior
            image = Image.open(internship_image)
            extracted_text = pytesseract.image_to_string(image, lang="eng")
            final_text = "\n".join(extracted_text).strip()
            if not final_text:
                raise ValueError("Upload a correct image. No readable text detected.")
            internship_data = parse_internship_details(extracted_text)
            
            return JsonResponse({
                "message": "Text extracted successfully", 
                "data": internship_data
            }, status=200)

    except Exception as e:
        return JsonResponse({"error": str(e)}, status=500)


def parse_internship_details(text):
    """Parses extracted text from an internship image into structured internship data.

    Args:
        text (str): The extracted text from the internship image.

    Returns:
        dict: A dictionary containing structured internship data.
    """
    text = re.sub(r"\n+", "\n", text).strip()

    title = _extract_field(text, ["Position", "Title"])
    company_name = _extract_field(text, ["Company Name", "Organization"])
    location = _extract_field(text, ["Location"], default="Remote")
    duration = _extract_field(text, ["Duration"], default="Not Mentioned")
    stipend = _extract_field(text, ["Stipend", "Salary"], default="Unpaid")
    application_deadline = _extract_field(text, ["Application Deadline", "Apply By"], default="2025-03-01")
    required_skills = _extract_list(text, ["Skills", "Required Skills"])
    job_description = _extract_field(text, ["Description", "Job Role"], default="Not Available")
    company_website = _extract_field(text, ["Website", "More Information"], default="Not Provided")
    internship_type = _extract_field(text, ["Internship Type"], default="Part-time")

    return {
        "title": title,
        "company_name": company_name,
        "location": location,
        "duration": duration,
        "stipend": stipend,
        "application_deadline": application_deadline,
        "required_skills": required_skills,
        "job_description": job_description,
        "company_website": company_website,
        "internship_type": internship_type
    }


def _extract_field(text, keywords, default=""):
    """Extracts a single field from the text based on keywords.

    Args:
        text (str): The text to search within.
        keywords (list): A list of keywords to search for.
        default (str): The default value if no match is found.

    Returns:
        str: The extracted field value, or the default value if no match is found.
    """
    for keyword in keywords:
        match = re.search(rf"{keyword}[:\-]?\s*(.*)", text, re.IGNORECASE)
        if match:
            return match.group(1).strip()
    return default


def _extract_list(text, keywords):
    """Extracts a list of values from the text based on keywords.

    Args:
        text (str): The text to search within.
        keywords (list): A list of keywords to search for.

    Returns:
        list: A list of extracted values.
    """
    for keyword in keywords:
        match = re.search(rf"{keyword}[:\-]?\s*(.*)", text, re.IGNORECASE)
        if match:
            return [skill.strip() for skill in match.group(1).split(",")]
    return []


@csrf_exempt
def post_internship(request):
    """Posts a new internship to the database.
    
    Supports both synchronous and asynchronous processing modes. When async=true is passed
    as a parameter, the internship creation happens in the background and a task ID is returned.

    Args:
        request (HttpRequest): The HTTP request object containing internship data.

    Returns:
        JsonResponse: A JSON response indicating success/failure or task ID if async.
    """
    if request.method != 'POST':
        return JsonResponse(
            {"error": "Invalid request method. Only POST is allowed."}, status=405)
    
    try:
        # Parse request data
        data_str = request.POST.get('data')
        data = json.loads(data_str)
        role = request.POST.get('role')
        userid = request.POST.get('userId')
        
        # Validate required fields
        required_fields = [
            'title', 'company_name', 'location', 'duration', 'stipend',
            'application_deadline', 'skills_required', 'job_description',
            'company_website', 'internship_type'
        ]
        
        for field in required_fields:
            if field not in data:
                return JsonResponse(
                    {"error": f"Missing required field: {field}"}, status=400)

        # Process image if provided
        image = request.FILES.get('image')
        image_base64 = None
        if image:
            try:
                image_base64 = base64.b64encode(image.read()).decode('utf-8')
            except Exception as e:
                logger.error("Error processing image: %s", str(e))
                return JsonResponse(
                    {"error": "Error processing image file"}, status=400)
        
        # Check if async processing is requested
        use_async = request.POST.get('async', '').lower() == 'true'
        
        if use_async:
            # Process asynchronously
            task_id = create_internship_post_async(data, role, userid, image_base64)
            
            # Return task information
            return JsonResponse({
                "message": "Internship submission started",
                "task_id": task_id,
                "status_url": f"/api/internship/task/{task_id}/status/"
            }, status=202)  # 202 Accepted
        else:
            # Original synchronous behavior
            # Get auto approval setting
            auto_approval_setting = superadmin_collection.find_one({"key": "auto_approval"})
            is_auto_approval = auto_approval_setting.get("value", False) if auto_approval_setting else False

            # Determine publication status based on role
            is_publish = None
            if role == 'admin' and is_auto_approval:
                is_publish = True
            elif role == 'superadmin':
                is_publish = True

            # Validate application deadline format
            application_deadline_str = data.get('application_deadline')
            try:
                application_deadline = datetime.strptime(
                    application_deadline_str, "%Y-%m-%d").replace(tzinfo=pytz.utc)
            except ValueError:
                return JsonResponse(
                    {"error": "Invalid date format for application_deadline. Use YYYY-MM-DD."},
                    status=400)

            # Determine internship status based on deadline
            now = timezone.now()
            current_status = "Active" if application_deadline >= now else "Expired"

            # Create internship document
            internship_post = {
                "internship_data": {
                    "title": data['title'],
                    "company_name": data['company_name'],
                    "location": data['location'],
                    "industry_type": data.get('industry_type', "NA"),
                    "duration": data['duration'],
                    "stipend": data['stipend'],
                    "application_deadline": application_deadline,
                    "required_skills": data['skills_required'],
                    "technical_skills": data.get('technical_skills', []),
                    "soft_skills": data.get('soft_skills', []),
                    "additional_skills": data.get('additional_skills', []),
                    "education_requirements": data.get('education_requirements', "NA"),
                    "job_description": data['job_description'],
                    "company_website": data['company_website'],
                    "internship_type": data['internship_type'],
                    "documents_required": data.get('documents_required', "NA"),
                    "internship_posting_date": data.get('internship_posting_date', "NA"),
                    "interview_start_date": data.get('interview_start_date', "NA"),
                    "interview_end_date": data.get('interview_end_date', "NA"),
                    "internship_link": data.get('internship_link', "NA"),
                    "selection_process": data.get('selection_process', "NA"),
                    "steps_to_apply": data.get('steps_to_apply', "NA"),
                    "image": image_base64
                },
                "admin_id" if role == "admin" else "superadmin_id": userid,
                "is_publish": is_publish,
                "status": current_status,
                "updated_at": timezone.now().isoformat()
            }

            internship_collection.insert_one(internship_post)

            return JsonResponse(
                {"message": "Internship posted successfully, awaiting approval."},
                status=200)

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
def manage_internships(request):
    """Retrieves internships based on the admin user's ID.

    Args:
        request (HttpRequest): The HTTP request object.

    Returns:
        JsonResponse: A JSON response containing a list of internships or an error message.
    """
    if request.method != 'GET':
        return JsonResponse({'error': 'Invalid request method'}, status=405)
    
    auth_header = request.headers.get('Authorization')
    if not auth_header or not auth_header.startswith("Bearer "):
        return JsonResponse({'error': 'No token provided'}, status=401)

    jwt_token = auth_header.split(" ")[1]

    try:
        # Decode and validate token
        decoded_token = jwt.decode(jwt_token, JWT_SECRET, algorithms=["HS256"])
        role = decoded_token.get('role')
        admin_user = (
            decoded_token.get('admin_user')
            if role == "admin" else decoded_token.get('superadmin_user')
        )

        if not admin_user:
            return JsonResponse({"error": "Invalid token"}, status=401)

        # Query internships based on role
        query = {"admin_id": admin_user} if role == "admin" else {}
        internships = internship_collection.find(query)
        
        # Format response data
        internship_list = []
        for internship in internships:
            internship["_id"] = str(internship["_id"])
            internship["views"] = len(internship.get("views", []))  # Add views count
            internship_list.append(internship)


        return JsonResponse({"internships": internship_list}, status=200)

    except jwt.ExpiredSignatureError:
        return JsonResponse({'error': 'JWT token has expired'}, status=401)
    except jwt.InvalidTokenError as e:
        return JsonResponse({'error': f'Invalid JWT token: {str(e)}'}, status=401)
    except Exception as e:
        return JsonResponse({'error': f'An error occurred: {str(e)}'}, status=400)


@csrf_exempt
def get_published_internships(request):
    """Retrieves all published internships.

    Args:
        request (HttpRequest): The HTTP request object.

    Returns:
        JsonResponse: A JSON response containing a list of published internships or an error message.
    """
    try:
        internship_list = []
        published_internships = internship_collection.find({"is_publish": True})
        
        for internship in published_internships:
            internship["_id"] = str(internship["_id"])
            total_views = len(internship.get("views", []))
            internship.pop("views", None)
            internship["views"] = total_views
            internship_list.append(internship)
            
        return JsonResponse({"internships": internship_list}, status=200)
    except Exception as e:
        return JsonResponse({"error": str(e)}, status=500)


@csrf_exempt
def review_internship(request, internship_id):
    """Approves or rejects an internship posting.

    Args:
        request (HttpRequest): The HTTP request object containing the action (approve/reject).
        internship_id (str): The ID of the internship to be reviewed.

    Returns:
        JsonResponse: A JSON response indicating success or failure.
    """
    if request.method != "POST":
        return JsonResponse({"error": "Invalid request method"}, status=400)
    
    try:
        data = json.loads(request.body)
        action = data.get("action")
        if action not in ["approve", "reject"]:
            return JsonResponse({"error": "Invalid action"}, status=400)

        # Verify internship exists
        internship = internship_collection.find_one({"_id": ObjectId(internship_id)})
        if not internship:
            return JsonResponse({"error": "Internship not found"}, status=404)

        # Update internship status
        is_publish = (action == "approve")
        internship_collection.update_one(
            {"_id": ObjectId(internship_id)},
            {"$set": {"is_publish": is_publish, "updated_at": datetime.now()}}
        )

        message = ("Internship approved and published successfully" 
                   if is_publish else "Internship rejected successfully")
        return JsonResponse({"message": message}, status=200)

    except Exception as e:
        return JsonResponse({"error": str(e)}, status=400)


@csrf_exempt
def get_internships(request):
    """Retrieves all internships with admin details.

    Args:
        request (HttpRequest): The HTTP request object.

    Returns:
        JsonResponse: A JSON response containing a list of internships with admin details or an error message.
    """
    try:
        internships = internship_collection.find()
        internship_list = []

        for internship in internships:
            internship["_id"] = str(internship["_id"])

            # Format application deadline
            if "application_deadline" in internship and internship["application_deadline"]:
                deadline = internship["application_deadline"]
                formatted_deadline = _format_deadline(deadline)
                internship["application_deadline"] = formatted_deadline

            # Get admin name
            admin_id = internship.get("admin_id")
            admin_name = "Unknown Admin"
            if admin_id:
                try:
                    admin = admin_collection.find_one({"_id": ObjectId(admin_id)})
                    if admin:
                        admin_name = admin.get("name", "Unknown Admin")
                except Exception as e:
                    print("Error fetching admin:", e)

            internship["admin_name"] = admin_name
            internship_list.append(internship)

        return JsonResponse({"internships": internship_list}, status=200)

    except Exception as e:
        return JsonResponse({"error": str(e)}, status=400)


def _format_deadline(deadline):
    """Helper function to format deadline dates consistently.
    
    Args:
        deadline: The deadline value to format (string or datetime)
        
    Returns:
        str: Formatted deadline as YYYY-MM-DD
    """
    try:
        if isinstance(deadline, datetime):
            return deadline.strftime("%Y-%m-%d")
        
        # Try different date formats
        try:
            return datetime.strptime(deadline, "%Y-%m-%dT%H:%M:%S.%fZ").strftime("%Y-%m-%d")
        except ValueError:
            try:
                return datetime.strptime(deadline, "%Y-%m-%d").strftime("%Y-%m-%d")
            except ValueError:
                pass
    except Exception:
        pass
    
    return deadline


@csrf_exempt
def get_internship_id(request, internship_id):
    """Retrieves a specific internship by its ID.

    Args:
        request (HttpRequest): The HTTP request object.
        internship_id (str): The ID of the internship to retrieve.

    Returns:
        JsonResponse: A JSON response containing the internship details or an error message.
    """
    if request.method != 'GET':
        return JsonResponse({"error": "Invalid method"}, status=405)
    
    try:
        internship = internship_collection.find_one({"_id": ObjectId(internship_id)})
        if not internship:
            return JsonResponse({"error": "Internship not found"}, status=404)

        internship["_id"] = str(internship["_id"])

        # Format application deadline
        if "application_deadline" in internship and internship["application_deadline"]:
            internship["application_deadline"] = _format_deadline(internship["application_deadline"])

        return JsonResponse({"internship": internship}, status=200)
    except Exception as e:
        return JsonResponse({"error": str(e)}, status=500)


@csrf_exempt
def delete_internship(request, internship_id):
    """Deletes an internship by its ID.

    Args:
        request (HttpRequest): The HTTP request object.
        internship_id (str): The ID of the internship to delete.

    Returns:
        JsonResponse: A JSON response indicating success or failure.
    """
    if request.method != 'DELETE':
        return JsonResponse({"error": "Invalid method"}, status=405)
    
    try:
        # Verify internship exists
        internship = internship_collection.find_one({"_id": ObjectId(internship_id)})
        if not internship:
            return JsonResponse({"error": "Internship not found"}, status=404)

        # Archive internship before deletion
        deleted_internship_collection.insert_one(internship)
        
        # Delete from active collection
        internship_collection.delete_one({"_id": ObjectId(internship_id)})

        return JsonResponse({"message": "Internship deleted successfully"}, status=200)
    except Exception as e:
        return JsonResponse({"error": str(e)}, status=500)


@csrf_exempt
def update_internship(request, internship_id):
    """Updates an existing internship.

    Args:
        request (HttpRequest): The HTTP request object containing updated internship data.
        internship_id (str): The ID of the internship to update.

    Returns:
        JsonResponse: A JSON response indicating success or failure.
    """
    if request.method != 'POST':
        return JsonResponse({"error": "Invalid request method. Only POST is allowed."}, status=405)
    
    try:
        # Verify internship exists
        internship = internship_collection.find_one({"_id": ObjectId(internship_id)})
        if not internship:
            return JsonResponse({"error": "Internship not found"}, status=404)

        # Extract data from form
        data_str = request.POST.get('data')
        if not data_str:
            return JsonResponse({"error": "No 'data' field in form"}, status=400)

        # Parse JSON data
        internship_data = json.loads(data_str)

        # Handle image upload
        image = request.FILES.get('image')
        if image:
            try:
                image_base64 = base64.b64encode(image.read()).decode('utf-8')
                internship_data['image'] = image_base64
            except Exception as e:
                logger.error(f"Error processing image: {str(e)}")
                return JsonResponse({"error": "Error processing image file"}, status=400)

        # Remove _id if present to avoid MongoDB errors
        if '_id' in internship_data:
            del internship_data['_id']

        # Handle edited flag separately if present
        edited_value = internship_data.pop("edited", None)

        # Create update operation with appropriate field mapping
        update_data = {"$set": {f"internship_data.{key}": value for key, value in internship_data.items()}}

        # Add edited flag to update if present
        if edited_value is not None:
            update_data["$set"]["edited"] = edited_value

        # Add timestamp
        update_data["$set"]["updated_at"] = timezone.now().isoformat()

        # Perform update
        internship_collection.update_one({"_id": ObjectId(internship_id)}, update_data)

        # Fetch updated internship
        updated_internship = internship_collection.find_one({"_id": ObjectId(internship_id)})
        updated_internship["_id"] = str(updated_internship["_id"])

        return JsonResponse({"message": "Internship updated successfully", "internship": updated_internship}, status=200)

    except json.JSONDecodeError as e:
        logger.error(f"JSON decode error: {str(e)}")
        return JsonResponse({"error": f"Invalid JSON data: {str(e)}"}, status=400)
    except InvalidId:
        return JsonResponse({"error": "Invalid internship ID format"}, status=400)
    except Exception as e:
        logger.error(f"Unexpected error: {str(e)}")
        return JsonResponse({"error": str(e)}, status=500)


@csrf_exempt
def get_internships_with_admin(request):
    """Retrieves all internships and maps them with admin names.

    Args:
        request (HttpRequest): The HTTP request object.

    Returns:
        JsonResponse: A JSON response containing internship details with admin names or an error message.
    """
    try:
        # Fetch only necessary fields to improve performance
        internships = internship_collection.find(
            {}, {"_id": 1, "admin_id": 1, "internship_data": 1, "updated_at": 1})

        internship_list = []

        for internship in internships:
            # Format internship data
            internship_id = str(internship["_id"])
            updated_at = internship.get("updated_at", "N/A")
            internship_data = internship.get("internship_data", {})
            
            # Get admin name
            admin_id = internship.get("admin_id")
            admin_name = "Super Admin"
            if admin_id:
                admin = admin_collection.find_one({"_id": ObjectId(admin_id)})
                if admin:
                    admin_name = admin.get("name", "Super Admin")

            # Create formatted internship object
            formatted_internship = {
                "internship_id": internship_id,
                "admin_name": admin_name,
                "message": f"{admin_name} posted an internship",
                "internship_data": {
                    "title": internship_data.get("title", "No title"),
                    "company": internship_data.get("company_name", "Not specified"),
                    "location": internship_data.get("location", "Unknown"),
                    "duration": internship_data.get("duration", "Unknown"),
                    "stipend": internship_data.get("stipend", "N/A"),
                    "deadline": internship_data.get("application_deadline", "N/A"),
                    "description": internship_data.get("job_description", "No description"),
                    "job_link": internship_data.get("job_link", "N/A"),
                    "education_requirements": internship_data.get("education_requirements", "N/A"),
                    "required_skills": internship_data.get("required_skills", []),
                    "internship_type": internship_data.get("internship_type", "N/A"),
                    "company_website": internship_data.get("company_website", "N/A"),
                    "status": internship_data.get("status", "N/A"),
                    "is_publish": internship_data.get("is_publish", False),
                },
                "timestamp": updated_at
            }
            
            internship_list.append(formatted_internship)

        return JsonResponse({"internships": internship_list}, status=200)

    except Exception as e:
        return JsonResponse({"error": str(e)}, status=500)