@echo off
echo Creating Python virtual environment...
python -m venv venv

echo Activating virtual environment...
call venv\Scripts\activate.bat

echo Installing dependencies...
pip install -r requirements.txt

echo Setup complete!
echo.
echo To run the application:
echo 1. Activate the virtual environment: venv\Scripts\activate.bat
echo 2. Start the server: python app.py
echo 3. Open browser to: http://localhost:5000
echo.
pause 