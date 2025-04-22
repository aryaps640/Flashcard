import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from django.conf import settings
from .models import User, OneTimePassword
from datetime import timedelta
from django.utils.timezone import now
import logging
logger = logging.getLogger(__name__)


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
            server.starttls()  # Upgrade the connection to a secure encrypted SSL/TTLS connection
            server.login(settings.EMAIL_HOST_USER, settings.EMAIL_HOST_PASSWORD)  # Login to the SMTP server
            server.sendmail(settings.DEFAULT_FROM_EMAIL, to_email, msg.as_string())  # Send the email
        logger.info(f"Email sent successfully to {to_email}")
    except Exception as e:
        logger.error(f"Failed to send email to {to_email}: {str(e)}")

def send_code_to_user(email):
    subject = "One Time Passcode for Email Verification"
    otp = generate_otp()
    body = f"Hi, use the passcode {otp} to verify your email. This code is valid for 1 minute."

    user = User.objects.get(email=email)
    otp_obj, created = OneTimePassword.objects.get_or_create(user=user)

    # Check if 1 minute has passed since the last OTP was sent
    if otp_obj.last_sent_at and now() < otp_obj.last_sent_at + timedelta(minutes=1):
        raise ValueError("You must wait 1 minute before requesting another OTP.")

    # Update the OTP and last_sent_at timestamp
    otp_obj.code = otp
    otp_obj.created_at = now()
    otp_obj.last_sent_at = now()
    otp_obj.save()

    send_email(subject, body, email)

def generate_otp():
    """
    Generates a 6-digit OTP code.

    Returns:
    - OTP code as a string
    """
    import random
    return "".join([str(random.randint(0, 9)) for _ in range(6)])


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