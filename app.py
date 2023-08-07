from flask import Flask, render_template, request, redirect, flash, url_for, session
import hashlib
import pymysql
import os
import boto3
from io import BytesIO
import json
secret_key = os.urandom(32)
app = Flask(__name__)
app.secret_key = secret_key

# Replace with your own RDS database credentials
DB_HOST = 'bheemreddy.cgcpjxhlj7ai.us-east-2.rds.amazonaws.com'
DB_USER = 'admin'
DB_PASSWORD = 'Prashanth48'
DB_DATABASE = 'filesharingdatabase'

# Replace with your own AWS credentials
AWS_ACCESS_KEY = "AKIAYCOUQXAUMV37BS5U"
AWS_SECRET_KEY ="wXZZKwJMbcbC5kC6Y6AlmWi4XcDuEZpFuy3ctX3c"
S3_BUCKET_NAME = 'filesharingbucket-pbheemre'
AWS_REGION = 'us-east-2'
LAMBDA_FUNCTION_NAME = 'send_Email'
LAMBDA_FUNCTION_ARN='arn:aws:lambda:us-east-2:555033344040:function:send_Email'
# Function to create a hashed password
def hash_password(password):
    salt = hashlib.sha256().hexdigest()[:16]
    return hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt.encode('utf-8'), 100000).hex()

# Function to connect to the RDS database
def connect_db():
    return pymysql.connect(
        host=DB_HOST,
        user=DB_USER,
        password=DB_PASSWORD,
        database=DB_DATABASE
    )

# Create users table in the database
def create_users_table():
    connection = connect_db()
    cursor = connection.cursor()
    query = """
        CREATE TABLE IF NOT EXISTS users (
            id INT AUTO_INCREMENT PRIMARY KEY,
            username VARCHAR(255) NOT NULL,
            email VARCHAR(255) NOT NULL UNIQUE,
            password VARCHAR(128) NOT NULL
        )
    """
    cursor.execute(query)
    connection.commit()
    cursor.close()
    connection.close()

# Function to upload file to S3 and notify recipients via Lambda function
# def upload_file_and_notify(file_path, recipient_emails_list):
#     try:
#         # Upload file to S3 bucket
#         s3_client = boto3.client('s3', aws_access_key_id=AWS_ACCESS_KEY, aws_secret_access_key=AWS_SECRET_KEY, region_name=AWS_REGION)
#         file_name = os.path.basename(file_path)
#         s3_client.upload_file(file_path, S3_BUCKET_NAME, file_name)

#         # Notify recipients via Lambda function
#         lambda_client = boto3.client('lambda', aws_access_key_id=AWS_ACCESS_KEY, aws_secret_access_key=AWS_SECRET_KEY, region_name=AWS_REGION)
#         payload = {
#             'file_url': f'https://{S3_BUCKET_NAME}.s3.amazonaws.com/{file_name}',
#             'recipient_emails': recipient_emails_list
#         }
#         response = lambda_client.invoke(FunctionName=LAMBDA_FUNCTION_NAME, Payload=str(payload))
#         return response['StatusCode'] == 200

#     except Exception as e:
#         print("Error:", e)
#         return False

def upload_file_and_notify(file, recipient_emails_list):
    try:
        # Generate a random file name to avoid conflicts
        random_filename = os.urandom(16).hex() + '-' + file.filename

        # Upload the file to S3 directly from memory
        s3_client = boto3.client('s3', aws_access_key_id=AWS_ACCESS_KEY, aws_secret_access_key=AWS_SECRET_KEY, region_name=AWS_REGION)
        file_bytes = file.read()
        s3_client.upload_fileobj(BytesIO(file_bytes), S3_BUCKET_NAME, random_filename)

        # Notify recipients via Lambda function
        # lambda_client = boto3.client('lambda', aws_access_key_id=AWS_ACCESS_KEY, aws_secret_access_key=AWS_SECRET_KEY, region_name=AWS_REGION)
        # payload = {
        #     'file_url': f'https://{S3_BUCKET_NAME}.s3.amazonaws.com/{random_filename}',
        #     'recipient_emails': recipient_emails_list
        # }
        # response = lambda_client.invoke(FunctionName=LAMBDA_FUNCTION_NAME, Payload=json.dumps(payload))
        return True

    except Exception as e:
        print("Error:", e)
        return False

@app.route('/')
def home():
    # You can add any logic here to render the home page
    # For example, you can redirect to the login page
    return redirect(url_for('login'))

# Function for user signup
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']

        connection = connect_db()
        cursor = connection.cursor()

        # Check if the user already exists
        query = "SELECT * FROM users WHERE email = %s"
        cursor.execute(query, (email,))
        existing_user = cursor.fetchone()
        if existing_user:
            cursor.close()
            connection.close()
            flash("User with this email already exists. Please try a different email.", "error")
            return redirect(url_for('signup'))

        # Hash the user password
        hashed_password = hash_password(password)

        # Create a new user record in the database
        query = "INSERT INTO users (username, email, password) VALUES (%s, %s, %s)"
        cursor.execute(query, (username, email, hashed_password))
        connection.commit()
        cursor.close()
        connection.close()

        flash("User signup successful! Please login.", "success")
        return redirect(url_for('login'))

    return render_template('signup.html')

# Function for user login
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        connection = connect_db()
        cursor = connection.cursor()

        # Find the user with the given email
        query = "SELECT * FROM users WHERE email = %s"
        cursor.execute(query, (email,))
        user = cursor.fetchone()
        cursor.close()
        connection.close()

        if user:
            # Verify the password
            hashed_password = user[3]  # user[3] is the hashed password stored in the database
            if hashed_password == hash_password(password):
                session['user_id'] = user[0]  # Store user_id in session for future use
                flash("Login successful!", "success")
                return redirect(url_for('dashboard'))
            else:
                flash("Incorrect password. Please try again.", "error")
                return render_template('login.html')
        else:
            flash("User not found. Please check your email or signup.", "error")
            return render_template('login.html')

    return render_template('login.html')

@app.route('/logout')
def logout():
    # Clear the user session to log them out
    session.clear()
    flash("You have been logged out.", "info")
    return redirect(url_for('login'))

# Dashboard route - accessible only after successful login
@app.route('/dashboard', methods=['GET', 'POST'])
def dashboard():
    if 'user_id' not in session:
        flash("Please login to access the dashboard.", "error")
        return redirect(url_for('login'))

    if request.method == 'POST':
        # Handle file upload and email notification here
        if 'file' not in request.files:
            flash("No file part in the request.", "error")
            return redirect(url_for('dashboard'))

        file = request.files['file']
        if file.filename == '':
            flash("No selected file.", "error")
            return redirect(url_for('dashboard'))

        # Get recipient emails from the form
        recipient_emails = request.form.get('emails')
        if not recipient_emails:
            flash("Please provide at least one email address.", "error")
            return redirect(url_for('dashboard'))

        recipient_emails_list = [email.strip() for email in recipient_emails.split(',')]
        if len(recipient_emails_list) > 5:
            flash("Please provide up to 5 email addresses.", "error")
            return redirect(url_for('dashboard'))

        # Save the uploaded file to a temporary location
        # Upload the file to S3 directly from memory and trigger the Lambda function
        if upload_file_and_notify(file, recipient_emails):
            flash("File uploaded and shared successfully!", "success")
        else:
            flash("An error occurred while uploading or sharing the file.", "error")

        return redirect(request.url)

    return render_template('dashboard.html')

if __name__ == '__main__':
    create_users_table()
    app.run(debug=True)
