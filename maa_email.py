# Version: 2026-03-27 v1.02
# Changes: Removed plaintext temporary password from welcome email (security fix). Email now tells user their password is expired and they will be prompted to change it on first login.
#!/usr/bin/env python3
import logging
import os
import smtplib
from email.mime.text import MIMEText
import socket
from io import StringIO
import subprocess
import time
SMTP_SERVER = 'internal-mail-router.oracle.com'
SMTP_PORT = 25
SMTP_USER = os.environ.get('SMTP_USER')
SMTP_PASSWORD = os.environ.get('SMTP_PASSWORD')
SENDER = 'MAA Unified App <maa_reports@oracle.com>'
SMTP_TIMEOUT = 30
SMTP_RETRIES = 3
SMTP_RETRY_DELAY = 5
def send_email(recipients, subject, body):
    """Send an email using SMTP with retries + sendmail fallback (exact alignment with email_agent_status.py)."""
    msg = MIMEText(body)
    msg['Subject'] = subject
    msg['From'] = SENDER
    msg['To'] = ', '.join(recipients) if isinstance(recipients, list) else recipients
    debug_output = StringIO()
    debug_handler = logging.StreamHandler(debug_output)
    debug_handler.setLevel(logging.DEBUG)
    debug_handler.setFormatter(logging.Formatter('%(message)s'))
    logging.getLogger('MAA_Unified').addHandler(debug_handler)
    for attempt in range(1, SMTP_RETRIES + 1):
        try:
            logging.getLogger('MAA_Unified').debug(f"Attempting SMTP connection to {SMTP_SERVER}:{SMTP_PORT} (attempt {attempt}/{SMTP_RETRIES})")
            server = smtplib.SMTP(SMTP_SERVER, SMTP_PORT, timeout=SMTP_TIMEOUT)
            try:
                if SMTP_USER and SMTP_PASSWORD:
                    logging.getLogger('MAA_Unified').debug("Initiating STARTTLS and authentication")
                    server.starttls()
                    server.login(SMTP_USER, SMTP_PASSWORD)
                logging.getLogger('MAA_Unified').debug(f"Sending email to {recipients}")
                server.sendmail(SENDER, recipients, msg.as_string())
                logging.getLogger('MAA_Unified').info("Email sent to %s via SMTP", recipients)
                return True
            finally:
                server.quit()
                debug_content = debug_output.getvalue()
                if debug_content:
                    logging.getLogger('MAA_Unified').debug("SMTP debug output:\n%s", debug_content)
        except (smtplib.SMTPException, socket.timeout, socket.error, OSError) as e:
            logging.getLogger('MAA_Unified').error("SMTP attempt %d failed: %s", attempt, str(e))
            if attempt < SMTP_RETRIES:
                logging.getLogger('MAA_Unified').info("Retrying in %d seconds...", SMTP_RETRY_DELAY)
                time.sleep(SMTP_RETRY_DELAY)
            else:
                logging.getLogger('MAA_Unified').error("All SMTP retries failed")
    logging.getLogger('MAA_Unified').removeHandler(debug_handler)
    debug_output.close()
    logging.getLogger('MAA_Unified').info("Falling back to sendmail")
    try:
        process = subprocess.Popen(['sendmail', '-t'], stdin=subprocess.PIPE, text=True)
        process.communicate(input=msg.as_string(), timeout=30)
        if process.returncode == 0:
            logging.getLogger('MAA_Unified').info("Email sent to %s via sendmail", recipients)
            return True
        else:
            logging.getLogger('MAA_Unified').error("Sendmail failed with exit code %d", process.returncode)
    except Exception as e:
        logging.getLogger('MAA_Unified').error("Sendmail error: %s", str(e))
    return False
def send_welcome_email(to_email, username):
    try:
        body = f"""Welcome to MAA Unified App!

Your account has been created.

Username: {username}

Your temporary password will  **expired* for security reasons after your first login.
You will be prompted to set a new password the first time you log in.

Login here: https://scaqaa04celadm12.us.oracle.com:6003/login

Temporary Credential Hint: we*****1
This is an automated message from the MAA Unified App.
"""
        if send_email([to_email], 'Your MAA Unified App Account', body):
            logging.getLogger('MAA_Unified').info(f"Welcome email sent to {to_email}")
            return True
        else:
            logging.getLogger('MAA_Unified').error(f"Failed to send welcome email to {to_email}")
            return False
    except Exception as e:
        logging.getLogger('MAA_Unified').error(f"Failed to send welcome email to {to_email}: {e}")
        return False
