# README and VIDEO
EventByte! Web application:

What does the web app use:

-sqlalchemy to create a database
-bcrypt to generate hash passwords and check them with the actual passwords in order to provide security
-barcodewriter and uuid to generate a barcode
-flask mail to send emails
-mailtrap sandbox smtp server to send emails
    Note: In my web app the smtp server i have used is a demo server, below i will provide the login details if you wish to test my web app and the smtp server
    E-mail: coursework.mail.test@gmail.com
    Password: courseworkmailtest

How the web app works:
-when registering, the app generates a random code and sends it to the email address provided in the form and then redirects you to the email verification template
-if the code submitted in the template matches the code sent to the email, the user is verified and then redirected to login
-the superuser is me, "ani". I have constructed the web app so only i can access the admin features
    Note: if you wish to test the web app and the admin features, the login details for the admin account are below:
    username: ani
    password: ani
-only the superuser can create and cancel events, decrease or increase capacity by 1, notified when the capacity is almost full, view the transaction log
    Note: In the demo video i changed the near capacity feature to 20% of the remaining tickets to make it easier to show how it works. In reality, i would have had to make the capacity much bigger for the test event and requested many tickets to reach near 5% capacity.
-the superuser can also use the webapp just like any another attendee
-all useres can view their tickets and its details in the "your tickets" tab, where they can also cancel the ticket and the "remaining capacity will increase by one
-all events are displayed in the "events" tab along with their details, including a status update, meaning that if the event gets cancelled the status will change to cancelled and the attendees with tickets will be notified.
-when creating an event all fields must be completed with the correct values and data types, otherwise it will result in an error and the databse will need to be reset
-the following events are logged:
    -user registration
    -user logging in
    -user requesting a ticket
    -user cancelling a ticket
    -event being cancelled
    -user logging out








Before submitting your coursework, run `./clean.sh` as this will remove the virtual environment which can be reconstructed locally.

