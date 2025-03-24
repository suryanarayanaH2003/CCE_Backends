from .admin_views import *
from .views import *
import threading
import queue
import time
import functools
from io import BytesIO
import logging


# Configure logger for async tasks
async_logger = logging.getLogger('async_study_material')
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

@async_task
def create_study_material_post_async(data, role, userid):
    """Create a study material post asynchronously.
    
    Args:
        data (dict): The study material data.
        role (str): The user role (admin/superadmin).
        userid (str): The user ID.
        
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
            
        # Prepare study material document
        study_material_post = {
            "type": data['type'],
            "title": data['title'],
            "description": data['description'],
            "category": data['category'],
            "links": data['links'],
            "admin_id" if role == "admin" else "superadmin_id": userid,
            "is_publish": is_publish,
            "updated_at": datetime.utcnow()
        }
        
        # Insert into database
        result = study_material_collection.insert_one(study_material_post)
        
        return {
            "message": "Study Material posted successfully.",
            "study_material_id": str(result.inserted_id)
        }
    except Exception as e:
        async_logger.error(f"Error creating study material: {str(e)}")
        raise

@csrf_exempt
def post_study_material(request):
    """Posts a new study material to the database.
    
    Supports both synchronous and asynchronous processing modes. When async=true is passed
    as a parameter, the study material creation happens in the background and a task ID is returned.

    Args:
        request (HttpRequest): The HTTP request object containing study material data.

    Returns:
        JsonResponse: A JSON response indicating success/failure or task ID if async.
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
        
        # Parse incoming JSON data
        data = json.loads(request.body)
        # Ensure required fields are present
        required_fields = ['type', 'title', 'description', 'category', 'links']
        for field in required_fields:
            if field not in data:
                return JsonResponse({"error": f"Missing required field: {field}"}, status=400)

        # Check if async processing is requested
        use_async = request.GET.get('async', '').lower() == 'true'

        if use_async:
            # Process asynchronously
            task_id = create_study_material_post_async(data, role, userid)
            
            # Return task information
            return JsonResponse({
                "message": "Study material submission started",
                "task_id": task_id,
                "status_url": f"/api/study_material/task/{task_id}/status/"
            }, status=202)  # 202 Accepted
        else:
            # Get auto approval setting
            auto_approval_setting = superadmin_collection.find_one({"key": "auto_approval"})
            is_auto_approval = auto_approval_setting.get("value", False) if auto_approval_setting else False

            # Determine publication status based on role
            is_publish = None
            if role == 'admin' and is_auto_approval:
                is_publish = True
            elif role == 'superadmin':
                is_publish = True
            
            # Prepare study material document
            study_material_post = {
                "type": data['type'],
                "title": data['title'],
                "description": data['description'],
                "category": data['category'],
                "links": data['links'],
                "admin_id" if role == "admin" else "superadmin_id": userid,
                "is_publish": is_publish,
                "updated_at": datetime.utcnow()
            }
            
            # Insert into MongoDB
            study_material_collection.insert_one(study_material_post)
            
            return JsonResponse({"message": "Study Material posted successfully"}, status=200)

    except json.JSONDecodeError:
        return JsonResponse({"error": "Invalid JSON format."}, status=400)
    except Exception as e:
        return JsonResponse({"error": str(e)}, status=500)

@async_task
def get_categories_async(material_type, query):
    """Get categories async."""
    try:
        import re
        # Create regex pattern for case-insensitive search
        regex_pattern = re.compile(f".*{re.escape(query)}.*", re.IGNORECASE)
        # Fetch distinct categories where:
        # - 'type' matches the provided type
        # - 'category' field exists
        # - 'category' matches the query (if any)
        categories = list(study_material_collection.distinct(
            "category",
            {
                "type": material_type,
                "category": {"$exists": True, "$regex": regex_pattern}
            }
        ))
        # Debugging logs
        if not categories:
            async_logger.info(f"No categories found for type '{material_type}'. Logging collection content:")
            for doc in study_material_collection.find({"type": material_type, "category": {"$exists": True}}):
                async_logger.info(doc)
        return {"categories": categories}
    except Exception as e:
        async_logger.error(f"Error get categories : {str(e)}")
        raise

@csrf_exempt
def get_categories(request):
    if request.method == 'GET':
        try:
            # Get query parameters
            material_type = request.GET.get('type')
            query = request.GET.get('query', '')
            if not material_type:
                return JsonResponse({"error": "Type parameter is required"}, status=400)
            # Check if async processing is requested
            use_async = request.GET.get('async', '').lower() == 'true'
            if use_async:
                # Process asynchronously
                task_id = get_categories_async(material_type,query)
                # Return task information
                return JsonResponse({
                    "message": "get categories submission started",
                    "task_id": task_id,
                    "status_url": f"/api/study_material/task/{task_id}/status/"
                }, status=202)  # 202 Accepted
            else:
                import re
                # Create regex pattern for case-insensitive search
                regex_pattern = re.compile(f".*{re.escape(query)}.*", re.IGNORECASE)
                # Fetch distinct categories where:
                # - 'type' matches the provided type
                # - 'category' field exists
                # - 'category' matches the query (if any)
                categories = list(study_material_collection.distinct(
                    "category",
                    {
                        "type": material_type,
                        "category": {"$exists": True, "$regex": regex_pattern}
                    }
                ))
                # Debugging logs
                if not categories:
                    print(f"No categories found for type '{material_type}'. Logging collection content:")
                    for doc in study_material_collection.find({"type": material_type, "category": {"$exists": True}}):
                        print(doc)
                return JsonResponse({"categories": categories}, status=200)
        except Exception as e:
            return JsonResponse({"error": str(e)}, status=500)
    return JsonResponse({"error": "Invalid request method. Only GET is allowed."}, status=405)

@async_task
def get_topics_by_category_async(category):
    """Get topics async."""
    try:
        # Use aggregation to unwind the links array and extract distinct topics
        pipeline = [
            {"$match": {"category": category}},
            {"$unwind": "$links"},
            {"$group": {"_id": "$links.topic"}},
            {"$project": {"_id": 0, "topic": "$_id"}}
        ]
        topics = list(study_material_collection.aggregate(pipeline))
        topics = [topic['topic'] for topic in topics]

        return {"topics": topics}
    except Exception as e:
        async_logger.error(f"Error get categories : {str(e)}")
        raise

@csrf_exempt
def get_topics_by_category(request):
    if request.method == 'GET':
        try:
            category = request.GET.get('category')
            if not category:
                return JsonResponse({"error": "Category is required"}, status=400)
             # Check if async processing is requested
            use_async = request.GET.get('async', '').lower() == 'true'
            if use_async:
                # Process asynchronously
                task_id = get_topics_by_category_async(category)
                # Return task information
                return JsonResponse({
                    "message": "get topic by categories submission started",
                    "task_id": task_id,
                    "status_url": f"/api/study_material/task/{task_id}/status/"
                }, status=202)  # 202 Accepted
            else:
                # Use aggregation to unwind the links array and extract distinct topics
                pipeline = [
                    {"$match": {"category": category}},
                    {"$unwind": "$links"},
                    {"$group": {"_id": "$links.topic"}},
                    {"$project": {"_id": 0, "topic": "$_id"}}
                ]
                topics = list(study_material_collection.aggregate(pipeline))
                topics = [topic['topic'] for topic in topics]

                return JsonResponse({"topics": topics}, status=200)

        except Exception as e:
            return JsonResponse({"error": str(e)}, status=500)

    return JsonResponse({"error": "Invalid request method. Only GET is allowed."}, status=405)

@async_task
def get_materials_by_topic_async(topic):
    try:
         # Use aggregation to unwind the links array and filter by topic
        pipeline = [
            {"$unwind": "$links"},
            {"$match": {"links.topic": topic}},
            {"$group": {
                "_id": "$_id",
                "type": {"$first": "$type"},
                "title": {"$first": "$title"},
                "description": {"$first": "$description"},
                "category": {"$first": "$category"},
                "links": {"$push": "$links"},
                "superadmin_id": {"$first": "$superadmin_id"},
                "is_publish": {"$first": "$is_publish"},
                "updated_at": {"$first": "$updated_at"}
            }}
        ]
        materials = list(study_material_collection.aggregate(pipeline))

        # Convert ObjectId to string
        for material in materials:
            material['_id'] = str(material['_id'])

        return {"materials": materials}

    except Exception as e:
        async_logger.error(f"Error get materials by topic : {str(e)}")
        raise

@csrf_exempt
def get_materials_by_topic(request):
    if request.method == 'GET':
        try:
            topic = request.GET.get('topic')
            if not topic:
                return JsonResponse({"error": "Topic is required"}, status=400)
             # Check if async processing is requested
            use_async = request.GET.get('async', '').lower() == 'true'
            if use_async:
                # Process asynchronously
                task_id = get_materials_by_topic_async(topic)
                # Return task information
                return JsonResponse({
                    "message": "get materials by topic submission started",
                    "task_id": task_id,
                    "status_url": f"/api/study_material/task/{task_id}/status/"
                }, status=202)  # 202 Accepted
            else:
                # Use aggregation to unwind the links array and filter by topic
                pipeline = [
                    {"$unwind": "$links"},
                    {"$match": {"links.topic": topic}},
                    {"$group": {
                        "_id": "$_id",
                        "type": {"$first": "$type"},
                        "title": {"$first": "$title"},
                        "description": {"$first": "$description"},
                        "category": {"$first": "$category"},
                        "links": {"$push": "$links"},
                        "superadmin_id": {"$first": "$superadmin_id"},
                        "is_publish": {"$first": "$is_publish"},
                        "updated_at": {"$first": "$updated_at"}
                    }}
                ]
                materials = list(study_material_collection.aggregate(pipeline))

                # Convert ObjectId to string
                for material in materials:
                    material['_id'] = str(material['_id'])

                return JsonResponse({"materials": materials}, status=200)

        except Exception as e:
            return JsonResponse({"error": str(e)}, status=500)

    return JsonResponse({"error": "Invalid request method. Only GET is allowed."}, status=405)

@async_task
def manage_study_materials_async(admin_user,role):
    try:
        # Fetch study materials from MongoDB based on admin_user
        study_materials = study_material_collection.find({"admin_id": admin_user} if role == "admin" else {})
        study_material_list = []
        for study in study_materials:
            study["_id"] = str(study["_id"])  # Convert ObjectId to string
            study_material_list.append(study)

        return {"study_materials": study_material_list}

    except Exception as e:
        async_logger.error(f"Error get manage study material: {str(e)}")
        raise

@csrf_exempt
def manage_study_materials(request):
    if request.method == 'GET':
        # Retrieve JWT token from Authorization Header
        auth_header = request.headers.get('Authorization')
        if not auth_header or not auth_header.startswith("Bearer "):
            return JsonResponse({'error': 'No token provided'}, status=401)

        jwt_token = auth_header.split(" ")[1]

        try:
            # Decode JWT token
            decoded_token = jwt.decode(jwt_token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
            role = decoded_token.get('role')
            admin_user = decoded_token.get('admin_user') if role == "admin" else decoded_token.get('superadmin_user')

            if not admin_user:
                return JsonResponse({"error": "Invalid token"}, status=401)
             # Check if async processing is requested
            use_async = request.GET.get('async', '').lower() == 'true'
            if use_async:
                # Process asynchronously
                task_id = manage_study_materials_async(admin_user,role)
                # Return task information
                return JsonResponse({
                    "message": "manage study materials submission started",
                    "task_id": task_id,
                    "status_url": f"/api/study_material/task/{task_id}/status/"
                }, status=202)  # 202 Accepted
            else:
                # Fetch study materials from MongoDB based on admin_user
                study_materials = study_material_collection.find({"admin_id": admin_user} if role == "admin" else {})
                study_material_list = []
                for study in study_materials:
                    study["_id"] = str(study["_id"])  # Convert ObjectId to string
                    study_material_list.append(study)

                return JsonResponse({"study_materials": study_material_list}, status=200)

        except jwt.ExpiredSignatureError:
            return JsonResponse({'error': 'JWT token has expired'}, status=401)
        except jwt.InvalidTokenError as e:
            return JsonResponse({'error': f'Invalid JWT token: {str(e)}'}, status=401)
        except Exception as e:
            return JsonResponse({'error': f'An error occurred: {str(e)}'}, status=400)
    else:
        return JsonResponse({'error': 'Invalid request method'}, status=405)

@async_task
def get_study_material_by_id_async(study_material_id):
    try:
        study_material = study_material_collection.find_one({"_id": ObjectId(study_material_id)})
        if not study_material:
            return {"error": "Study material not found"}

        study_material["_id"] = str(study_material["_id"])  # Convert ObjectId to string
        return {"study_material": study_material}
    except Exception as e:
        async_logger.error(f"Error get study material by id: {str(e)}")
        raise

@csrf_exempt
def get_study_material_by_id(request, study_material_id):
    """
    Fetch a single study material by its ID.
    """
    try:
             # Check if async processing is requested
            use_async = request.GET.get('async', '').lower() == 'true'
            if use_async:
                # Process asynchronously
                task_id = get_study_material_by_id_async(study_material_id)
                # Return task information
                return JsonResponse({
                    "message": "get study material by id submission started",
                    "task_id": task_id,
                    "status_url": f"/api/study_material/task/{task_id}/status/"
                }, status=202)  # 202 Accepted
            else:
                study_material = study_material_collection.find_one({"_id": ObjectId(study_material_id)})
                if not study_material:
                    return JsonResponse({"error": "Study material not found"}, status=404)

                study_material["_id"] = str(study_material["_id"])  # Convert ObjectId to string
                return JsonResponse({"study_material": study_material}, status=200)
    except Exception as e:
        return JsonResponse({"error": str(e)}, status=500)


@async_task
def update_study_material_async(study_material_id, data):
    try:

        study_material = study_material_collection.find_one({"_id": ObjectId(study_material_id)})
        if not study_material:
            return {"error": "Study material not found"}

        # Exclude the _id field from the update
        if '_id' in data:
            del data['_id']

        study_material_collection.update_one({"_id": ObjectId(study_material_id)}, {"$set": data})
        updated_study_material = study_material_collection.find_one({"_id": ObjectId(study_material_id)})
        updated_study_material["_id"] = str(updated_study_material["_id"])  # Convert ObjectId to string
        return {"study_material": updated_study_material}
    except Exception as e:
        async_logger.error(f"Error update study material : {str(e)}")
        raise

@csrf_exempt
def update_study_material(request, study_material_id):
    """
    Update a study material by its ID.
    """
    if request.method == 'PUT':
        try:
            data = json.loads(request.body)
             # Check if async processing is requested
            use_async = request.GET.get('async', '').lower() == 'true'
            if use_async:
                # Process asynchronously
                task_id = update_study_material_async(study_material_id,data)
                # Return task information
                return JsonResponse({
                    "message": "update study material submission started",
                    "task_id": task_id,
                    "status_url": f"/api/study_material/task/{task_id}/status/"
                }, status=202)  # 202 Accepted
            else:
                study_material = study_material_collection.find_one({"_id": ObjectId(study_material_id)})
                if not study_material:
                    return JsonResponse({"error": "Study material not found"}, status=404)

                # Exclude the _id field from the update
                if '_id' in data:
                    del data['_id']

                study_material_collection.update_one({"_id": ObjectId(study_material_id)}, {"$set": data})
                updated_study_material = study_material_collection.find_one({"_id": ObjectId(study_material_id)})
                updated_study_material["_id"] = str(updated_study_material["_id"])  # Convert ObjectId to string
                return JsonResponse({"study_material": updated_study_material}, status=200)
        except Exception as e:
            return JsonResponse({"error": str(e)}, status=500)
    else:
        return JsonResponse({"error": "Invalid method"}, status=405)

@async_task
def delete_study_material_async(study_material_id):
    try:
        study_material = study_material_collection.find_one({"_id": ObjectId(study_material_id)})
        if not study_material:
            return {"error": "Study material not found"}

        study_material_collection.delete_one({"_id": ObjectId(study_material_id)})
        return {"message": "Study material deleted successfully"}
    except Exception as e:
        async_logger.error(f"Error delete study material : {str(e)}")
        raise

@csrf_exempt
def delete_study_material(request, study_material_id):
    """
    Delete a study material by its ID.
    """
    if request.method == 'DELETE':
        try:
             # Check if async processing is requested
            use_async = request.GET.get('async', '').lower() == 'true'
            if use_async:
                # Process asynchronously
                task_id = delete_study_material_async(study_material_id)
                # Return task information
                return JsonResponse({
                    "message": "delete study material submission started",
                    "task_id": task_id,
                    "status_url": f"/api/study_material/task/{task_id}/status/"
                }, status=202)  # 202 Accepted
            else:
                study_material = study_material_collection.find_one({"_id": ObjectId(study_material_id)})
                if not study_material:
                    return JsonResponse({"error": "Study material not found"}, status=404)

                study_material_collection.delete_one({"_id": ObjectId(study_material_id)})
                return JsonResponse({"message": "Study material deleted successfully"}, status=200)
        except Exception as e:
            return JsonResponse({"error": str(e)}, status=500)
    else:
        return JsonResponse({"error": "Invalid method"}, status=405)

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

    
@async_task
def get_study_materials_with_admin_async():
    """Retrieves all study materials and maps them with admin names asynchronously."""
    try:
        # Fetch only necessary fields to improve performance
        study_materials = study_material_collection.find(
            {}, {"_id": 1, "admin_id": 1, "title": 1, "description": 1, "category": 1, "links": 1, "updated_at": 1})

        study_material_list = []

        for material in study_materials:
            # Format study material data
            material_id = str(material["_id"])
            updated_at = material.get("updated_at", "N/A")
            title = material.get("title", "No title")
            description = material.get("description", "No description")
            category = material.get("category", "No category")
            links = material.get("links", [])
            
            # Get admin name
            admin_id = material.get("admin_id")
            admin_name = "Super Admin"
            if admin_id:
                admin = admin_collection.find_one({"_id": ObjectId(admin_id)})
                if admin:
                    admin_name = admin.get("name", "Super Admin")

            # Create formatted study material object
            formatted_material = {
                "study_material_id": material_id,
                "admin_name": admin_name,
                "message": f"{admin_name} shared a study material",
                "study_material_data": {
                    "title": title,
                    "description": description,
                    "category": category,
                    "links": links
                },
                "timestamp": updated_at
            }
            
            study_material_list.append(formatted_material)

        return {"study_materials": study_material_list}

    except Exception as e:
        async_logger.error(f"Error in get_study_materials_with_admin_async: {str(e)}")
        raise

@csrf_exempt
def get_study_materials_with_admin(request):
    """Retrieves all study materials and maps them with admin names.

    Args:
        request (HttpRequest): The HTTP request object.

    Returns:
        JsonResponse: A JSON response containing study material details with admin names or an error message.
    """
    try:
        use_async = request.GET.get('async', '').lower() == 'true'
        if use_async:
            task_id = get_study_materials_with_admin_async()
            return JsonResponse({
                "message": "get study material with admin submission started",
                "task_id": task_id,
                "status_url": f"/api/study_material/task/{task_id}/status/"
            }, status=202)
        else:
            # Fetch only necessary fields to improve performance
            study_materials = study_material_collection.find(
                {}, {"_id": 1, "admin_id": 1, "title": 1, "description": 1, "category": 1, "links": 1, "updated_at": 1})

            study_material_list = []

            for material in study_materials:
                # Format study material data
                material_id = str(material["_id"])
                updated_at = material.get("updated_at", "N/A")
                title = material.get("title", "No title")
                description = material.get("description", "No description")
                category = material.get("category", "No category")
                links = material.get("links", [])

                # Get admin name
                admin_id = material.get("admin_id")
                admin_name = "Super Admin"
                if admin_id:
                    admin = admin_collection.find_one({"_id": ObjectId(admin_id)})
                    if admin:
                        admin_name = admin.get("name", "Super Admin")

                # Create formatted study material object
                formatted_material = {
                    "study_material_id": material_id,
                    "admin_name": admin_name,
                    "message": f"{admin_name} shared a study material",
                    "study_material_data": {
                        "title": title,
                        "description": description,
                        "category": category,
                        "links": links
                    },
                    "timestamp": updated_at
                }

                study_material_list.append(formatted_material)

            return JsonResponse({"study_materials": study_material_list}, status=200)

    except Exception as e:
        return JsonResponse({"error": str(e)}, status=500)