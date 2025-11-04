# Gebruik een lichte Python base image
FROM python:3.11-slim

# Zet werkdirectory
WORKDIR /app

# Kopieer en installeer dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Kopieer je applicatiecode
COPY . .

# Expose poort
EXPOSE 8000

# Start de app
CMD ["uvicorn", "Api:app", "--host", "0.0.0.0", "--port", "8000"]
