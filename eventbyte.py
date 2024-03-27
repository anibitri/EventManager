from flask import Flask, render_template, request, redirect, url_for, flash, abort
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship, backref
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from datetime import datetime
import barcode
from barcode.writer import ImageWriter
from uuid import uuid4
import os
from flask_mail import Mail, Message
from werkzeug.utils import secure_filename
import string, random
from werkzeug.security import generate_password_hash, check_password_hash

#app configuration
app = Flask(__name__)
# Get the absolute path to the directory containing the Flask app
BASE_DIR = os.path.abspath(os.path.dirname(__file__))

# Define the path to the SQLite database file relative to the app directory
DB_FILE = os.path.join(BASE_DIR, 'mydb1.db')

# Set the SQLALCHEMY_DATABASE_URI using the constructed file path
app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{DB_FILE}'
app.config['SECRET_KEY'] = 'your_secret_key_here'
db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
mail = Mail()

#flask-mail configuration
app.config['MAIL_SERVER']='sandbox.smtp.mailtrap.io'
app.config['MAIL_PORT'] = 2525
app.config['MAIL_USERNAME'] = '5cd69e80cc5a45'
app.config['MAIL_PASSWORD'] = 'ee9638ca15fb04'
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USE_SSL'] = False

mail.init_app(app)

#database tables
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(60), nullable=False)
    verification_code = db.Column(db.String(6), nullable=False)
    verified = db.Column(db.Boolean, nullable=False, default=False)

    @property
    def password(self):
        raise AttributeError('Password is not a readable attribute')

    @password.setter
    def password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class Event(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    location = db.Column(db.String(255), nullable=False)
    date = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    capacity = db.Column(db.Integer, nullable=False)
    creator_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    creator = db.relationship('User', backref='events', foreign_keys=[creator_id])
    cancelled = db.Column(db.Boolean, nullable=False, default=False)
    duration = db.Column(db.String(50), nullable=False)
    remaining_capacity = db.Column(db.Integer, nullable=True)

    def is_full(self):
        return len(self.tickets) >= self.capacity
    
    def increase_capacity(self):
        self.capacity += 1

    def decrease_capacity(self):
        self.capacity -= 1

class Ticket(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    event_id = db.Column(db.Integer, db.ForeignKey('event.id'), nullable=False)
    event = db.relationship('Event', backref='tickets')
    attendee_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    attendee = db.relationship('User', backref='tickets')
    barcode = db.Column(db.String(128), unique=True, nullable=False)

class TransactionLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    user = db.relationship('User', backref='transactions')
    action = db.Column(db.String(100), nullable=False)
    details = db.Column(db.Text)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


#generating random verivication code
def generate_verification_code():
    return ''.join(random.choices(string.ascii_letters + string.digits, k=6))

#function to send the verification code to the users email
def send_verification_email(user):
    verification_code = generate_verification_code()
    msg = Message("Verify Your Email", sender="noreply@example.com", recipients=[user.email])
    msg.body = f"Your verification code is: {verification_code}"
    mail.send(msg)
    # Store the verification code in the user object
    user.verification_code = verification_code
    db.session.commit()

#generating a barcode for a ticket to an event
def generate_barcode(ticket_id):
    ticket = Ticket.query.get(ticket_id)
    if ticket:
        barcode_value = barcode.get_barcode_class('code128')
        barcode_image = barcode_value(ticket.barcode, writer=ImageWriter())
        barcode_image.save(f'static/barcodes/{ticket.barcode}.png')

#index
@app.route('/')
def home():
    return render_template('index.html', events=events)


#route for registration
@app.route('/templates/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']  # New: Get email from form
        password = request.form['password']
        verification_code = generate_verification_code()
        user = User(username=username, email=email, verification_code=verification_code)  # New: Create user with email
        user.password = password
        db.session.add(user)
        db.session.commit()

        send_verification_email(user)

        log_entry = TransactionLog(user_id=user.id, action='User Registered', details=f'User: {user.username} has registered')
        db.session.add(log_entry)
        db.session.commit()
        flash('Your account has been created! You are now able to log in', 'success')
        return redirect(url_for('verify_email', email = user.email))
    return render_template('register.html')

#after registration, send verification code to registered email address
@app.route('/templates/verify_email', methods=['GET', 'POST'])
def verify_email():
    if request.method == 'GET':
        email = request.args.get('email')  # Get email from query parameters
        if not email:
            flash('Invalid email address.', 'error')
            return redirect(url_for('register'))

        user = User.query.filter_by(email=email).first()
        if not user:
            flash('Invalid email address.', 'error')
            return redirect(url_for('register'))

    if request.method == 'POST':
        email = request.form.get('email')  # Get email from form data
        user = User.query.filter_by(email=email).first()
        if not user:
            flash('Invalid email address.', 'error')
            return redirect(url_for('register'))

        verification_code = request.form['verification_code']
        if verification_code == user.verification_code:
            user.verified = True
            db.session.commit()
            # Email verified, redirect to login page
            flash('Email verified successfully.', 'success')
            return redirect(url_for('login'))  # Redirect to login page
        else:
            flash('Invalid verification code.', 'error')

    return render_template('verify_email.html', email=email)

#route for login
@app.route('/templates/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password):
            if user.verified:
                login_user(user)
                # Log user login
                log_entry = TransactionLog(user_id=user.id, action='User Login', details=f'User: {user.username} logged in')
                db.session.add(log_entry)
                db.session.commit()
                flash('You have been logged in!', 'success')
                return redirect(url_for('events'))
            else:
                return redirect(url_for('verify_email', email=user.email))
        else:
            flash('Login unsuccessful. Please check your credentials', 'danger')

    return render_template('login.html')

#after logging in, the events webpage is displayed
@app.route('/templates/events')
@login_required
def events():
    events = Event.query.all()
    for event in events:
        allocated_tickets = len(event.tickets)
        #calculating the remaining tickects for an event
        remaining_capacity = event.capacity - allocated_tickets
        event.remaining_capacity = remaining_capacity
    return render_template('events.html', events=events)

#route to create an event, only the admin "ani" can do this
@app.route('/templates/create_event', methods=['GET', 'POST'])
@login_required
def create_event():
    if current_user.username != 'ani':
        flash('You do not have permission to access this page.', 'danger')
        return redirect(url_for('events'))

    if request.method == 'POST':
        title = request.form['title']
        location = request.form['location']
        datetime_str = request.form['datetime']
        capacity = request.form['capacity']
        duration = request.form['duration']
            
        # Convert the datetime string to a Python datetime object
        datetime_obj = datetime.strptime(datetime_str, '%Y-%m-%dT%H:%M')
        
        # Create the event object
        event = Event(title=title, location=location, date=datetime_obj, capacity=capacity, creator_id=current_user.id, duration = duration, remaining_capacity = capacity)
        db.session.add(event)
        db.session.commit()

        #log the creation of the event
        log_entry = TransactionLog(user_id=current_user.id, action='Event Created', details=f'Event: {event.title} created')
        db.session.add(log_entry)
        db.session.commit()

        flash('Event created successfully!', 'success')
        return redirect(url_for('events'))
    
    return render_template('create_event.html')

#route to check capacity for an event
@app.route("/check_capacity/<int:event_id>")
def check_capacity(event_id):
    event = Event.query.get(event_id)
    if event:
        allocated_tickets = len(event.tickets)
        capacity = event.capacity
        remaining_capacity = capacity - allocated_tickets
        if remaining_capacity <= 0:
            return 'Event is already full'
        elif remaining_capacity <= 0.05 * capacity:  # Less than 5% capacity remaining
            admin_email = 'test.flask.mail.2@gmail.com'
            msg = Message(
                'Event Capacity Alert',
                sender='test.flask.mail.2@gmail.com',
                recipients=[admin_email]
            )
            msg.body = f'Event "{event.title}" is less than 5% capacity available. Remaining capacity: {remaining_capacity}/{capacity}'
            mail.send(msg)
            return 'Email sent to admin'
        else:
            return 'Event capacity is sufficient'
    else:
        return 'Event not found'


#route to request a ticket to an event
@app.route('/request_ticket/<int:event_id>', methods=['GET', 'POST'])
@login_required
def request_ticket(event_id):
    event = Event.query.get_or_404(event_id)
    if request.method == 'POST' :
        if event.cancelled:
            flash('Event is cancelled. No tickets can be redeemed.', 'warning')
            return redirect(url_for('events'))
        
        # Check if there are available tickets remaining
        if len(event.tickets) >= event.capacity:
            flash('Event is full. No more tickets available!', 'warning')
            return redirect(url_for('events'))
        
        # Generate a unique barcode for the ticket
        barcode = str(uuid4())
        
        # Create a new ticket with the generated barcode
        ticket = Ticket(event_id=event.id, attendee_id=current_user.id, barcode=barcode)
        
        # Add the ticket to the database
        db.session.add(ticket)
        db.session.commit()

        log_entry = TransactionLog(user_id=current_user.id, action='Ticket Allocated', details=f'Ticket to: {event.title} allocated to: {current_user.username}')
        db.session.add(log_entry)
        db.session.commit()

        check_capacity(event_id)

        flash('Ticket obtained successfully!', 'success')
    return redirect(url_for('events'))

#route to increase capacity for an event, only the admin "ani" can do this
@app.route('/increase_capacity/<int:event_id>', methods=['POST'])
@login_required
def increase_capacity(event_id):
    event = Event.query.get_or_404(event_id)
    if current_user.username == 'ani' and not event.cancelled:
        event.increase_capacity()
        db.session.commit()
        flash('Capacity increased successfully!', 'success')
    return redirect(url_for('events'))

#route to decrease capacity for an event, only the admin "ani" can do this
@app.route('/decrease_capacity/<int:event_id>', methods=['POST'])
@login_required
def decrease_capacity(event_id):
    event = Event.query.get_or_404(event_id)
    if current_user.username == 'ani' and not event.cancelled and event.capacity > 0:
        event.decrease_capacity()
        db.session.commit()
        flash('Capacity decreased successfully!', 'success')
    return redirect(url_for('events'))

#route to cancel an event, only the admin "ani" can do this
@app.route('/cancel_event/<int:event_id>', methods=['POST'])
@login_required
def cancel_event(event_id):
    event = Event.query.get_or_404(event_id)
    if current_user.username == 'ani':
        # Fetch unique attendees associated with the event
        attendees = set(ticket.attendee for ticket in event.tickets)

        # Update event status to cancelled
        event.cancelled = True
        db.session.commit()

        # Send email notification to each unique attendee
        for attendee in attendees:
            msg = Message(
                'Event Cancellation Alert',
                sender='flask.mail.test.2@gmail.com',  # Update with sender email
                recipients=[attendee.email]
            )
            msg.body = f'Dear {attendee.username},\n\nThe event "{event.title}" has been cancelled.\n\nSincerely,\nThe Event Team'
            mail.send(msg)

        # Log event cancellation
        log_entry = TransactionLog(user_id=current_user.id, action='Event Cancelled', details=f'Event: {event.title} cancelled')
        db.session.add(log_entry)
        db.session.commit()

        flash('Event cancelled successfully!', 'success')
    else:
        flash('You are not allowed to cancel events.', 'danger')
    return redirect(url_for('events'))

#route for attendees to cancel their ticket
@app.route('/cancel_ticket/<int:ticket_id>', methods=['POST'])
@login_required
def cancel_ticket(ticket_id):
    ticket = Ticket.query.get(ticket_id)
    if request.method == 'POST':
        if ticket:
            if ticket.attendee_id == current_user.id:
                # Update remaining capacity
                event = Event.query.get(ticket.event_id)
                event.remaining_capacity += 1
                db.session.delete(ticket)
                db.session.commit()

                # Log ticket cancellation
                log_entry = TransactionLog(user_id=current_user.id, action='Ticket Cancelled', details=f'User has cancelled their ticket for {ticket.event.title}')
                db.session.add(log_entry)
                db.session.commit()
                flash('Ticket cancelled successfully!', 'success')
            else:
                flash('You are not authorized to cancel this ticket.', 'error')
        else:
            flash('Ticket not found.', 'error')

    return redirect(url_for('user_events'))

#route to display the events that an attendee has tickets to
@app.route('/templates/user_events')
@login_required
def user_events():
    tickets = Ticket.query.filter_by(attendee_id=current_user.id).all()
    return render_template('user_events.html', tickets=tickets)

#route to transaction log, only the admin "ani" has access to this
@app.route('/templates/transaction_log')
@login_required
def admin_transaction_log():
    if current_user.username != 'ani':
        abort(403)  # Forbidden if user is not admin
    transactions = TransactionLog.query.all()
    return render_template('admin_transaction_log.html', transactions=transactions)

#route to logout user
@app.route('/logout')
@login_required
def logout():
    log_entry = TransactionLog(user_id=current_user.id, action='User Logout', details=f'User: {current_user.username} logged out')
    db.session.add(log_entry)
    db.session.commit()
    logout_user()
    return redirect(url_for('home'))

if __name__ == '__main__':
    db.create_all()
    app.run(debug=True)