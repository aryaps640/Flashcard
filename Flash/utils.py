import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from django.conf import settings
from .models import User, OneTimePassword

def send_email(subject, body, to_email):
    """
    Sends an email using SMTP.

    Parameters:
    - subject: Subject of the email
    - body: Body of the email
    - to_email: Recipient's email address
    """
    # Create message container
    msg = MIMEMultipart()
    msg['From'] = settings.DEFAULT_FROM_EMAIL
    msg['To'] = to_email
    msg['Subject'] = subject

    # Attach the email body
    msg.attach(MIMEText(body, 'plain'))

    try:
        # Connect to the SMTP server
        with smtplib.SMTP(settings.EMAIL_HOST, settings.EMAIL_PORT) as server:
            server.starttls()  # Upgrade the connection to a secure encrypted SSL/TLS connection
            server.login(settings.EMAIL_HOST_USER, settings.EMAIL_HOST_PASSWORD)  # Login to the SMTP server
            server.sendmail(settings.DEFAULT_FROM_EMAIL, to_email, msg.as_string())  # Send the email
        print(f"Email sent successfully to {to_email}")
    except Exception as e:
        print(f"Failed to send email: {str(e)}")

import random
from django.core.mail import send_mail
from django.conf import settings

def generate_otp():
    """Generate a 6-digit random OTP."""
    return str(random.randint(100000, 999999))

def send_code_to_user(email, otp):
    """Send OTP to the user via email."""
    subject = "Your OTP Code for Email Verification"
    message = f"Your OTP code is {otp}. It is valid for 5 minutes. Do not share it with anyone."
    from_email = settings.EMAIL_HOST_USER
    recipient_list = [email]

    send_mail(subject, message, from_email, recipient_list)


def send_normal_email(data):
    """
    Sends a normal email with the given data.

    Parameters:
    - data: Dictionary containing 'email_subject', 'email_body', and 'to_email'
    """
    subject = data.get('email_subject')
    body = data.get('email_body')
    to_email = data.get('to_email')
    
    send_email(subject, body, to_email)