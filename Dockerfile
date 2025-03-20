# Use an official Python image
FROM python:3.12
# Set the working directory
WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    tesseract-ocr \
    libtesseract-dev \
    libgl1-mesa-glx \
    libglib2.0-0 \
    && rm -rf /var/lib/apt/lists/*


RUN apt-get update \
    && apt-get -y install tesseract-ocr

# Copy project files
COPY . .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Set the Tesseract path inside the container
ENV TESSERACT_CMD=/usr/bin/tesseract

# Expose the port your Django app runs on
EXPOSE 8000

# Run the Django server
CMD ["gunicorn", "--bind", "0.0.0.0:8000", "backend.wsgi:application"]

