from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
import json
from datetime import datetime
import jwt
from bson import ObjectId
from pymongo import MongoClient
import os
from dotenv import load_dotenv
from django.core.validators import validate_email
from django.core.exceptions import ValidationError

load_dotenv()

# JWT Configuration
JWT_SECRET = os.environ.get("JWT_SECRET", "secret")
JWT_ALGORITHM = "HS256"

# MongoDB Configuration
MONGO_URI = os.environ.get("MONGO_URI")
MONGODB_TIMEOUT_MS = os.environ.get("MONGODB_TIMEOUT_MS")

DATABASE_NAME = "CCE"
MESSAGE_COLLECTION_NAME = "message"

# Global MongoDB Connection
_mongo_client = None
_message_collection = None

def get_message_collection():
    """
    Establishes and returns a connection to the MongoDB message collection.
    Maintains a global connection for reuse.  If the connection is lost, it attempts to reconnect.

    Returns:
        pymongo.collection.Collection: The MongoDB message collection.
    """
    global _mongo_client, _message_collection
    try:
        if _mongo_client is None:
            _mongo_client = MongoClient(MONGO_URI,serverSelectionTimeoutMS=MONGODB_TIMEOUT_MS)
            _message_collection = _mongo_client[DATABASE_NAME][MESSAGE_COLLECTION_NAME]
        # Check if the connection is still alive by performing a simple operation
        _mongo_client.admin.command('ping')
        return _message_collection
    except Exception as e:
        print(f"Error connecting to MongoDB: {e}")
        # Attempt to reconnect
        _mongo_client = None
        return get_message_collection()


def create_response(message, status_code, error=None):
    """
    Creates a standardized JSON response.

    Args:
        message (str): The message to be included in the response.
        status_code (int): The HTTP status code for the response.
        error (str, optional): An error message to be included in the response. Defaults to None.

    Returns:
        JsonResponse: A JSON response containing the message and optional error, with the specified status code.
    """
    response_data = {"message": message}
    if error:
        response_data["error"] = error
    return JsonResponse(response_data, status=status_code)

def create_message_entry(sender, content):
    """
    Creates a message entry for the chat.

    Args:
        sender (str): The sender of the message ("student" or "admin").
        content (str): The content of the message.

    Returns:
        dict: A dictionary representing the message entry.
    """
    message_entry = {
        "sender": sender,
        "content": content,
        "timestamp": datetime.now(),
        "status": "sent"
    }
    return message_entry

@csrf_exempt
def contact_us(request):
    """
    Handles the contact form submission.  Accepts POST requests with student ID, email, and message content.
    Validates input and either creates a new chat or adds the message to an existing chat in the database.

    Args:
        request (HttpRequest): The HTTP request object.

    Returns:
        JsonResponse: A JSON response indicating the success or failure of the message submission.
    """
    if request.method == "POST":
        try:
            data = json.loads(request.body)
            student_id = data.get("student_id")
            student_email = data.get("student_email")
            content = data.get("message")

            # Input Validation
            if not all([student_id, student_email, content]):
                return create_response("All fields are required", 400, "Missing data")

            try:
                validate_email(student_email)
            except ValidationError as e:
                return create_response("Invalid email address", 400, str(e))

            # Get the collection
            message_collection = get_message_collection()

            # Create message entry
            message_entry = create_message_entry("student", content)

            # Check if chat exists and update or create
            chat = message_collection.find_one({"student_id": student_id})

            if chat:
                message_collection.update_one(
                    {"student_id": student_id},
                    {"$push": {"messages": message_entry}}
                )
            else:
                new_chat = {
                    "student_id": student_id,
                    "student_email": student_email,
                    "messages": [message_entry]
                }
                message_collection.insert_one(new_chat)

            return create_response("Message sent successfully!", 200)

        except json.JSONDecodeError:
            return create_response("Invalid JSON", 400, "JSONDecodeError")
        except Exception as e:
            return create_response("An error occurred", 500, str(e))

    return create_response("Invalid request method", 405)


@csrf_exempt
def get_student_messages(request, student_id):
    """
    Retrieves messages for a specific student.  Requires a valid JWT for authentication.
    Only allows access to the student's own messages or by a superadmin.

    Args:
        request (HttpRequest): The HTTP request object.
        student_id (str): The ID of the student whose messages are being retrieved.

    Returns:
        JsonResponse: A JSON response containing the student's messages, or an error message if access is denied or the token is invalid.
    """
    if request.method == "GET":
        try:
            # 🔹 Extract JWT from Authorization header
            auth_header = request.headers.get("Authorization")
            if not auth_header or not auth_header.startswith("Bearer "):
                return create_response("No token provided", 401, "Missing or invalid Authorization header")

            token = auth_header.split("Bearer ")[1]  # Extract token

            try:
                decoded_token = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
                student_user = decoded_token.get("student_user", None)
                superadmin_id = decoded_token.get("superadmin_user", None)  #  Fix: Use `superadmin_user`

                #  Fix: Allow SuperAdmin or the correct student to access messages
                if superadmin_id or (student_user == student_id):
                    pass  # Authorization successful
                else:
                    return create_response("Unauthorized access", 403, "Insufficient permissions")

            except jwt.ExpiredSignatureError:
                return create_response("Token expired", 401, "ExpiredSignatureError")
            except jwt.InvalidTokenError:
                return create_response("Invalid token", 401, "InvalidTokenError")

            # Fetch messages
            message_collection = get_message_collection()

            # Add a validation to check that the users
            chat = message_collection.find_one({"student_id": str(student_id)}, {"_id": 0, "messages": 1})

            if not chat:
                return JsonResponse({"messages": []}, status=200)

            return JsonResponse({"messages": chat.get("messages", [])}, status=200)

        except Exception as e:
            return create_response("An error occurred", 500, str(e))

    return create_response("Invalid request method", 405)

@csrf_exempt
def student_send_message(request):
    """
    Allows a student to send a message. Requires a valid student_id and message content in the request body.
    Validates the student_id against the database.

    Args:
        request (HttpRequest): The HTTP request object.

    Returns:
        JsonResponse: A JSON response indicating the success or failure of the message submission.
    """
    if request.method == "POST":
        try:
            data = json.loads(request.body)
            student_id = data.get("student_id")
            content = data.get("content")

            if not all([student_id, content]):
                return create_response("All fields are required", 400, "Missing data")

            # Input validation: check if student_id exists in the database
            message_collection = get_message_collection()
            student_chat = message_collection.find_one({"student_id": student_id})
            if not student_chat:
                return create_response("Student ID not found", 400, "Invalid student_id")


            message_entry = create_message_entry("student", content)

            result = message_collection.update_one(
                {"student_id": student_id},
                {"$push": {"messages": message_entry}}
            )

            if result.modified_count == 0:
                return create_response("Chat not found", 404, "ChatNotFound")

            return create_response("Message sent successfully!", 200)

        except json.JSONDecodeError:
            return create_response("Invalid JSON", 400, "JSONDecodeError")
        except Exception as e:
            return create_response("An error occurred", 500, str(e))

    return create_response("Invalid request method", 405)


@csrf_exempt
def get_all_student_chats(request):
    """
    Retrieves a list of all student chats (IDs and emails).  Requires a valid JWT for authentication.
    Only allows access by a superadmin.

    Args:
        request (HttpRequest): The HTTP request object.

    Returns:
        JsonResponse: A JSON response containing the list of student chats, or an error message if access is denied or the token is invalid.
    """
    if request.method == "GET":
        try:
            #Implement checks to ensure that the user requesting this information has the necessary permissions
            auth_header = request.headers.get("Authorization")
            if not auth_header or not auth_header.startswith("Bearer "):
                return create_response("No token provided", 401, "Missing or invalid Authorization header")

            token = auth_header.split("Bearer ")[1]  # Extract token
            try:
                decoded_token = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
                superadmin_id = decoded_token.get("superadmin_user", None)  # ✅ Fix: Use `superadmin_user`

                if not superadmin_id:
                     return create_response("Unauthorized access", 403, "Insufficient permissions")
            except jwt.ExpiredSignatureError:
                return create_response("Token expired", 401, "ExpiredSignatureError")
            except jwt.InvalidTokenError:
                return create_response("Invalid token", 401, "InvalidTokenError")

            message_collection = get_message_collection()
            chats = list(message_collection.find({}, {"_id": 1, "student_id": 1, "student_email": 1}))

            for chat in chats:
                chat["_id"] = str(chat["_id"])

            return JsonResponse({"chats": chats}, status=200)

        except Exception as e:
            return create_response("An error occurred", 500, str(e))

    return create_response("Invalid request method", 405)

@csrf_exempt
def admin_reply_message(request):
    """
    Allows an admin to reply to a student message. Requires a valid student_id and message content in the request body.
    Validates the student_id against the database.

    Args:
        request (HttpRequest): The HTTP request object.

    Returns:
        JsonResponse: A JSON response indicating the success or failure of the message reply.
    """
    if request.method == "POST":
        try:
            data = json.loads(request.body)
            student_id = data.get("student_id")
            content = data.get("content")

            if not all([student_id, content]):
                return create_response("All fields are required", 400, "Missing data")
             # Input validation: check if student_id exists in the database
            message_collection = get_message_collection()
            student_chat = message_collection.find_one({"student_id": student_id})
            if not student_chat:
                return create_response("Student ID not found", 400, "Invalid student_id")

            message_entry = create_message_entry("admin", content)

            result = message_collection.update_one(
                {"student_id": student_id},
                {"$push": {"messages": message_entry}}
            )

            if result.modified_count == 0:
                return create_response("Chat not found", 404, "ChatNotFound")

            return create_response("Reply sent successfully!", 200)

        except json.JSONDecodeError:
            return create_response("Invalid JSON", 400, "JSONDecodeError")
        except Exception as e:
            return create_response("An error occurred", 500, str(e))

    return create_response("Invalid request method", 405)


@csrf_exempt
def mark_messages_as_seen_by_admin(request, student_id):
    """
    Marks all student messages in a chat as "seen" by the admin.  Requires a valid JWT for authentication.
    Only allows access by a superadmin.

    Args:
        request (HttpRequest): The HTTP request object.
        student_id (str): The ID of the student whose chat is being modified.

    Returns:
        JsonResponse: A JSON response indicating the success or failure of marking the messages as seen.
    """
    if request.method == 'POST':
        try:
            #Implement checks to ensure that the user requesting this information has the necessary permissions
            auth_header = request.headers.get("Authorization")
            if not auth_header or not auth_header.startswith("Bearer "):
                return create_response("No token provided", 401, "Missing or invalid Authorization header")

            token = auth_header.split("Bearer ")[1]  # Extract token
            try:
                decoded_token = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
                superadmin_id = decoded_token.get("superadmin_user", None)  # ✅ Fix: Use `superadmin_user`

                if not superadmin_id:
                     return create_response("Unauthorized access", 403, "Insufficient permissions")
            except jwt.ExpiredSignatureError:
                return create_response("Token expired", 401, "ExpiredSignatureError")
            except jwt.InvalidTokenError:
                return create_response("Invalid token", 401, "InvalidTokenError")

            message_collection = get_message_collection()

            # Find the student's chat document
            student_chat = message_collection.find_one({"student_id": student_id})

            if student_chat:
                # Update the status of all messages to "seen"
                for message in student_chat.get("messages", []):
                    if message["sender"] == "student" and message["status"] == "sent":
                        message["status"] = "seen"

                # Update the document in the database
                message_collection.update_one(
                    {"_id": ObjectId(student_chat["_id"])},
                    {"$set": {"messages": student_chat["messages"]}}
                )

                return create_response("Messages marked as seen.", 200)
            else:
                return create_response("Student chat not found.", 404, "ChatNotFound")
        except Exception as e:
            return create_response("An error occurred", 500, str(e))
    else:
        return create_response("Invalid request method.", 405)

@csrf_exempt
def mark_messages_as_seen_by_student(request, student_id):
    """
    Marks messages from admin as "seen" by the student. Requires a valid JWT for authentication.
    Only allows the student to mark their own messages as seen.

    Args:
        request (HttpRequest): The HTTP request object.
        student_id (str): The ID of the student whose chat is being modified.

    Returns:
        JsonResponse: A JSON response indicating the success or failure of marking the messages as seen.
    """
    if request.method == 'POST':
        try:
            #Implement checks to ensure that the user requesting this information has the necessary permissions
            auth_header = request.headers.get("Authorization")
            if not auth_header or not auth_header.startswith("Bearer "):
                return create_response("No token provided", 401, "Missing or invalid Authorization header")

            token = auth_header.split("Bearer ")[1]  # Extract token
            try:
                decoded_token = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
                student_user = decoded_token.get("student_user", None)  # ✅ Fix: Use `superadmin_user`

                if not student_user or student_user != student_id:
                     return create_response("Unauthorized access", 403, "Insufficient permissions")
            except jwt.ExpiredSignatureError:
                return create_response("Token expired", 401, "ExpiredSignatureError")
            except jwt.InvalidTokenError:
                return create_response("Invalid token", 401, "InvalidTokenError")
            message_collection = get_message_collection()
            # Find the student's chat document
            student_chat = message_collection.find_one({"student_id": student_id})

            if student_chat:
                # Update the status of all messages from admin to "seen"
                messages = student_chat.get("messages", [])
                for message in messages:
                    if message["sender"] == "admin" and message["status"] == "sent":
                        message["status"] = "seen"

                # Update the document in the database
                message_collection.update_one(
                    {"_id": ObjectId(student_chat["_id"])},
                    {"$set": {"messages": messages}}
                )

                return create_response("Messages marked as seen.", 200)
            else:
                return create_response("Student chat not found.", 404, "ChatNotFound")
        except Exception as e:
            return create_response("An error occurred", 500, str(e))
    else:
        return create_response("Invalid request method.", 405)