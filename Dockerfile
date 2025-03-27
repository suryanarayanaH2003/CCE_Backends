# Use an official Python image
FROM python:3.12

# Set the working directory
WORKDIR /app

# Install system dependencies (including Tesseract OCR)
RUN apt-get update && apt-get install -y \
    tesseract-ocr \
    libtesseract-dev \
    libgl1-mesa-glx \
    libglib2.0-0 \
    && rm -rf /var/lib/apt/lists/*

# Copy project files
COPY . .

# Install Python dependencies
RUN pip install --upgrade pip && pip install -r requirements.txt

# Set the Tesseract path inside the container
ENV TESSERACT_CMD=/usr/bin/tesseract

# Expose the port your Django app runs on
EXPOSE 8000

# Start Gunicorn (properly set CMD)
CMD ["gunicorn", "--bind=0.0.0.0:8000", "backend.wsgi:application", 
     "--log-level=debug", "--access-logfile=access.log", "--error-logfile=error.log"]
