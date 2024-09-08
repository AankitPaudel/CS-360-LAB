from flask_mail import Message
from app import mail, app
from flask import url_for, flash
import traceback

def send_reset_email(user):
    token = user.get_reset_token()
    msg = Message('Password Reset Request',
                  sender='noreply@yourdomain.com',
                  recipients=[user.email])
    msg.body = f'''To reset your password, visit the following link:
{url_for('main.reset_token', token=token, _external=True)}

If you did not make this request then simply ignore this email and no changes will be made.
'''

    print("Using MAIL_PASSWORD:", app.config['MAIL_PASSWORD'])

    try:
        mail.send(msg)
    except Exception as e:
        app.logger.error('Failed to send email', exc_info=e)
        flash('An error occurred when sending the email. Please try again later.', 'danger')
        app.logger.error(traceback.format_exc())
