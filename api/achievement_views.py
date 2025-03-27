from .internship_views import *
from .job_views import *
from .admin_views import *
from .study_material_views import *
from .exam_views import *
from .views import *

import threading
import queue
import time
import functools
import logging

DATABASE_URL = os.environ.get(
    "DATABASE_URL", 'mongodb+srv://ihub:ihub@cce.ksniz.mongodb.net/')
DATABASE_NAME = "CCE"
client = MongoClient(DATABASE_URL)
db = client[DATABASE_NAME]

ACHIEVEMENT_COLLECTION_NAME = "achievement"
achievement_collection = db[ACHIEVEMENT_COLLECTION_NAME]

# Configure logger for async tasks
async_logger = logging.getLogger('async_achievement')
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
@csrf_exempt
def post_achievement(request):
    """Posts a new achievement to the database with image handling.

    Args:
        request (HttpRequest): The HTTP request object containing achievement data.

    Returns:
        JsonResponse: A JSON response indicating success/failure.
    """
    if request.method != 'POST':
        return JsonResponse(
            {"error": "Invalid request method. Only POST is allowed."}, status=405)
    
    try:
        # Get JWT token from Authorization Header
        auth_header = request.headers.get('Authorization')
        if not auth_header or not auth_header.startswith("Bearer "):
            return JsonResponse({"error": "No token provided"}, status=401)
        jwt_token = auth_header.split(" ")[1]
        
        # Decode JWT token
        try:
            decoded_token = jwt.decode(jwt_token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        except jwt.ExpiredSignatureError:
            return JsonResponse({"error": "Token expired"}, status=401)
        except jwt.InvalidTokenError:
            return JsonResponse({"error": "Invalid token"}, status=401)
        
        role = decoded_token.get('role')
        userid = decoded_token.get('admin_user') if role == "admin" else decoded_token.get('superadmin_user')
        
        # Extract data from request
        name = request.POST.get("name")
        achievement_description = request.POST.get("achievement_description")
        achievement_type = request.POST.get("achievement_type")
        company_name = request.POST.get("company_name")
        date_of_achievement = request.POST.get("date_of_achievement")
        batch = request.POST.get("batch")
        image = request.FILES.get("photo")

        # Validate required fields
        if not userid:
            return JsonResponse(
                {"error": "user_id not found"}, status=401)

        # Get auto approval setting
        auto_approval_setting = superadmin_collection.find_one({"key": "auto_approval"})
        is_auto_approval = auto_approval_setting.get("value", False) if auto_approval_setting else False

        # Determine publication status based on role
        is_publish = None
        if role == 'admin' and is_auto_approval:
            is_publish = True
        elif role == 'superadmin':
            is_publish = True

        # Process image
        image_base64 = None
        if image:
            try:
                image_base64 = base64.b64encode(image.read()).decode('utf-8')
            except Exception as e:
                async_logger.error(f"Error processing image: {str(e)}")
                return JsonResponse({"error": "Error processing image file"}, status=400)

        # Prepare achievement data
        achievement_data = {
            "name": name,
            "achievement_description": achievement_description,
            "achievement_type": achievement_type,
            "company_name": company_name,
            "date_of_achievement": date_of_achievement,
            "batch": batch,
            "admin_id" if role == "admin" else "superadmin_id": userid,
            "created_by": role,
            "is_publish": is_publish,
            "updated_at": datetime.now(),
            "photo": image_base64,  # Store base64 encoded image
        }
        
        # Insert into MongoDB
        achievement_collection.insert_one(achievement_data)
        
        return JsonResponse(
            {"message": "Achievement stored successfully."},
            status=201)
    except Exception as e:
        return JsonResponse({"error": str(e)}, status=500)
    
@csrf_exempt
def manage_achievements(request):
    """Retrieves achievements based on the admin user's ID.

    Args:
        request (HttpRequest): The HTTP request object.

    Returns:
        JsonResponse: A JSON response containing a list of achievements or an error message.
    """
    if request.method != 'GET':
        return JsonResponse({'error': 'Invalid request method'}, status=405)
    
    auth_header = request.headers.get('Authorization')
    if not auth_header or not auth_header.startswith("Bearer "):
        return JsonResponse({'error': 'No token provided'}, status=401)

    jwt_token = auth_header.split(" ")[1]

    try:
        # Decode and validate token
        decoded_token = jwt.decode(jwt_token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        role = decoded_token.get('role')
        admin_user = (
            decoded_token.get('admin_user')
            if role == "admin" else decoded_token.get('superadmin_user')
        )

        if not admin_user:
            return JsonResponse({"error": "Invalid token"}, status=401)
      
        # Fetch the data
        achievements = achievement_collection.find(
            {"admin_id": admin_user} if role == "admin" else {})
        
        # Format response data
        achievement_list = [{**achievement, "_id": str(achievement["_id"])}
                            for achievement in achievements]

        return JsonResponse({"achievements": achievement_list}, status=200)

    except jwt.ExpiredSignatureError:
        return JsonResponse({'error': 'JWT token has expired'}, status=401)
    except jwt.InvalidTokenError as e:
        return JsonResponse({'error': f'Invalid JWT token: {str(e)}'}, status=401)
    except Exception as e:
        return JsonResponse({'error': f'An error occurred: {str(e)}'}, status=400)

@csrf_exempt
def update_achievement(request, achievement_id):
    """Updates an achievement by its ID.

    Args:
        request (HttpRequest): The HTTP request object containing updated achievement data.
        achievement_id (str): The ID of the achievement to be updated.

    Returns:
        JsonResponse: A JSON response containing the updated achievement or an error message.
    """
    if request.method != 'PUT':
        return JsonResponse({"error": "Invalid method"}, status=405)
    
    try:
        data = json.loads(request.body)

        # Handle image upload
        image = request.FILES.get("photo")
        image_base64 = None

        if image:
            try:
                image_base64 = base64.b64encode(image.read()).decode('utf-8')
            except Exception as e:
                async_logger.error(f"Error processing image: {str(e)}")
                return JsonResponse({"error": "Error processing image file"}, status=400)

        # Process asynchronously
        achievement = achievement_collection.find_one(
            {"_id": ObjectId(achievement_id)})

        if not achievement:
            return JsonResponse({"error": "Achievement not found"}, status=404)

        if '_id' in data:
            del data['_id']
        
        if image_base64:
            data["photo"] = image_base64

        data["updated_at"] = datetime.now()
        achievement_collection.update_one(
            {"_id": ObjectId(achievement_id)}, {"$set": data})

        updated_achievement = achievement_collection.find_one(
            {"_id": ObjectId(achievement_id)})
        updated_achievement["_id"] = str(updated_achievement["_id"])

        return JsonResponse({"achievement": updated_achievement}, status=200)

    except Exception as e:
        return JsonResponse({"error": str(e)}, status=500)
    
@csrf_exempt
def get_achievements(request):
    """Retrieves all achievements from the database.

    Args:
        request (HttpRequest): The HTTP request object.

    Returns:
        JsonResponse: A JSON response containing a list of achievements or an error message.
    """
    try:
        achievements = achievement_collection.find()
        achievement_list = [{**achievement, "_id": str(achievement["_id"])}
                            for achievement in achievements]
        return JsonResponse({"achievements": achievement_list}, status=200)
    except Exception as e:
        return JsonResponse({"error": str(e)}, status=500)

@csrf_exempt
def get_achievement_by_id(request, achievement_id):
    """Retrieves a specific achievement by its ID.

    Args:
        request (HttpRequest): The HTTP request object.
        achievement_id (str): The ID of the achievement to retrieve.

    Returns:
        JsonResponse: A JSON response containing achievement details or an error message.
    """
    try:
        achievement = achievement_collection.find_one(
            {"_id": ObjectId(achievement_id)})
        if not achievement:
            return JsonResponse({"error": "Achievement not found"}, status=404)

        achievement["_id"] = str(achievement["_id"])
        return JsonResponse({"achievement": achievement}, status=200)
    except Exception as e:
        return JsonResponse({"error": str(e)}, status=500)

@csrf_exempt
def get_published_achievements(request):
    """Retrieves all published achievements.

    Args:
        request (HttpRequest): The HTTP request object.

    Returns:
        JsonResponse: A JSON response containing a list of published achievements or an error message.
    """
    try:
        published_achievements = achievement_collection.find({"is_publish": True})
        achievement_list = [{**achievement, "_id": str(achievement["_id"])}
                            for achievement in published_achievements]
        return JsonResponse({"achievements": achievement_list}, status=200)
    except Exception as e:
        return JsonResponse({"error": str(e)}, status=500)

@csrf_exempt
def get_achievements_with_admin(request):
    """Retrieves all achievements and maps them with admin names.

    Args:
        request (HttpRequest): The HTTP request object.

    Returns:
        JsonResponse: A JSON response containing achievement details with admin names or an error message.
    """
    try:
        achievements = achievement_collection.find(
            {}, {"_id": 1, "admin_id": 1, "achievement_description": 1,
                 "achievement_type": 1, "company_name": 1, "date_of_achievement": 1,
                 "updated_at": 1})

        achievement_list = []

        for achievement in achievements:
            achievement_id = str(achievement["_id"])
            updated_at = achievement.get("updated_at", "N/A")

            admin_id = achievement.get("admin_id")
            admin_name = "Super Admin"

            if admin_id:
                admin = admin_collection.find_one({"_id": ObjectId(admin_id)})
                if admin:
                    admin_name = admin.get("name", "Super Admin")

            achievement_list.append({
                "achievement_id": achievement_id,
                "admin_name": admin_name,
                "message": f"{admin_name} posted an achievement",
                "achievement_data": {
                    "description": achievement.get("achievement_description", "No description"),
                    "type": achievement.get("achievement_type", "Unknown"),
                    "company": achievement.get("company_name", "Not specified"),
                    "date": achievement.get("date_of_achievement", "Unknown"),
                },
                "timestamp": updated_at
            })

        return JsonResponse({"achievements": achievement_list}, status=200)

    except Exception as e:
        return JsonResponse({"error": str(e)}, status=500)

@csrf_exempt
def achievement_detail(request, achievement_id):
    """Retrieves or updates a specific achievement.

    Args:
        request (HttpRequest): The HTTP request object.
        achievement_id (str): The ID of the achievement to retrieve or update.

    Returns:
        JsonResponse: A JSON response containing achievement details or an error message.
    """
    try:
        try:
            object_id = ObjectId(achievement_id)
        except:
            return JsonResponse(
                {"error": "Invalid Achievement ID"}, status=400)

        achievement = achievement_collection.find_one({"_id": object_id})
        if not achievement:
            return JsonResponse(
                {"error": "Achievement not found"}, status=404)

        if request.method == 'GET':
            achievement["_id"] = str(achievement["_id"])
            return JsonResponse(achievement, status=200, safe=False)

        elif request.method == 'PUT':
            updated_data = json.loads(request.body)
            achievement_collection.update_one(
                {"_id": object_id},
                {"$set": updated_data}
            )
            return JsonResponse(
                {"message": "Achievement updated successfully"}, status=200)
    except Exception as e:
        return JsonResponse({"error": str(e)}, status=500)
    
@async_task
def delete_achievement_async(achievement_id):
    """Deletes an achievement by its ID asynchronously."""
    try:
        result = achievement_collection.delete_one({"_id": ObjectId(achievement_id)})

        if result.deleted_count == 0:
            return {"error": "Achievement not found"}

        return {"message": "Achievement deleted successfully"}
    except Exception as e:
        async_logger.error(f"Error deleting achievement: {str(e)}")
        raise

@csrf_exempt
def delete_achievement(request, achievement_id):
    """Deletes an achievement by its ID.

    Args:
        request (HttpRequest): The HTTP request object.
        achievement_id (str): The ID of the achievement to be deleted.

    Returns:
        JsonResponse: A JSON response indicating success or failure.
    """
    if request.method != 'DELETE':
        return JsonResponse({"error": "Invalid method"}, status=405)

    try:
        delete_achievement_async(achievement_id)
        return JsonResponse({"message": "Achievement deleted successfully"}, status=200)
    except Exception as e:
        return JsonResponse({"error": str(e)}, status=500)