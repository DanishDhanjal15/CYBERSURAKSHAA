To run the frontend and backend of this project, you can use the commands detailed below. Since you are on Windows, the instructions are tailored for it.

Step 1: Set Up & Activate Virtual Environment
Open your terminal (PowerShell or Command Prompt) and navigate to the project directory:

powershell
cd "c:\Users\Danish\OneDrive\Desktop\danish betting\betting_detector"
Activate the virtual environment:

PowerShell:
powershell
.venv\Scripts\Activate.ps1
Command Prompt (CMD):
cmd
.venv\Scripts\activate.bat
(If you haven't installed dependencies yet, run pip install -r requirements.txt inside the activated environment.)

Step 2: Run the Backend (FastAPI API)
With the virtual environment activated, run the following command to start the FastAPI server:

powershell
python app.py
API URL: http://localhost:8000
Swagger API Docs (Interactive): http://localhost:8000/docs
Step 3: Run the Frontend (Streamlit Dashboard)
Open a new terminal window/tab, navigate to the same directory, activate the virtual environment, and run:

powershell
streamlit run dashboard/app.py
Dashboard URL: http://localhost:8501
Alternatively: Run with Docker Compose
If you have Docker installed and want to run both components together:

powershell
cd "c:\Users\Danish\OneDrive\Desktop\danish betting\betting_detector"
docker-compose up --build
This starts both the backend API and frontend dashboard automatically.

8:07 PM
8:11 PM
Based on the logs, the FastAPI backend is currently starting up but has not finished initializing its machine learning models yet.

During this startup phase, the server is running but does not yet accept network connections, which is why the Streamlit frontend reports it as "API Offline".

Why is it taking time?
In your .env file, you have USE_BERT=true. On startup, the application pre-warms (downloads/loads into memory) three heavy models sequentially:

PaddleOCR (took ~2 minutes to initialize)
DistilBERT text classifier (takes ~45 seconds)
YOLOv8 object detector (takes ~5–10 seconds)
How to resolve:
Just wait 1–2 minutes: Watch the terminal where python app.py is running. Once you see the following log message:

text
🚀 All components ready — Betting Detector API is live.
refresh the Streamlit page (http://localhost:8501) and the message will turn into ✅ API Online.

Make startup faster (Optional): If you want the backend to start up in under 5 seconds for development, you can disable the heavy BERT classifier and fallback to the TF-IDF/Keyword classifier. To do this, open your .env file and change:

env
USE_BERT=false
Then restart the backend (python app.py).