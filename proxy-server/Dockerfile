FROM python:3.11-slim

WORKDIR /app

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application files
COPY . .

# Create log directory
RUN mkdir -p /var/log/waf

# Expose port
EXPOSE 8080

# Run application
CMD ["uvicorn", "proxy:app", "--host", "0.0.0.0", "--port", "8080", "--log-level", "info"]