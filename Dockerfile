# Gebruik een officiële Python image
FROM python:3.11-slim

# Zet werkdirectory
WORKDIR /app

# Kopieer requirements (je kunt dit aanpassen als je geen requirements.txt hebt)
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

# Kopieer je API-code
COPY . .

# Expose de poort waarop Uvicorn draait
EXPOSE 8000

# Start de FastAPI-server
CMD ["uvicorn", "Api:app", "--host", "0.0.0.0", "--port", "8000"]
