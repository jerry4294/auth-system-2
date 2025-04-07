README.md

### Prerequisites
Install these:
- [Node.js](https://nodejs.org/) v18+
- [MongoDB](https://www.mongodb.com/) (local instance or Atlas cloud)
- [Git](https://github.com/)

### Clone the Repository

	In terminal 
git clone https://github.com/jerry4294/auth-system-2.git 
cd auth-system-2

### Install Dependencies
npm install 
	Dependencies
Package	Purpose
express	Web framework
mongoose	MongoDB interaction
bcryptjs	Password hashing
jsonwebtoken	JWT creation and validation
cookie-parser	Parses cookies, used for JWT auth
dotenv	Environment variables (.env file)
cors	Cross-origin requests handling
validator	Input sanitization and email checks
passport	Authentication framework
passport-google-oauth20	Google OAuth strategy

### Run the application
npm start / node server.js 
	it will run at http://localhost:5000 

### Input Validation Techniques
To avoid logic errors, injection, and XSS, input validation is essential.

Field	Validation Applied
username	required, only alphanumeric, 3–20 characters
email	Regex pattern + validator.isEmail()
password	6 chars minimum, no spaces, strict complexity guidelines
role	Must be either user or admin, from enum list


	Libraries 
1.	Validator: for input sanitization and email format.
2.	Express-validator: used for scalable validation.

### Output Encoding 

While being an API-based application, we comply to secure response encoding guidelines.

	Methods Used  
1.	There is no HTML rendering on the server.
2.	JSON answers don't ever include executable data.
3.	Use of textContent or .innerText rather than innerHTML.

	Protection Against XSS
If this were a server-rendered application, like as one that uses handlebars or EJS:
1.	To encrypt HTML-sensitive characters, use escape-html.
2.	In template engines, auto-escaping output stops <script> injection.

Encryption Techniques

Password Hashing
1. Passwords are never kept in plaintext.
2.  Library: bcryptjs

 Token Security 
1. Tokens are signed using a JWT secret.
2. Safely kept in HTTP-only cookies:
 - httpOnly: true
 - secure: true (on HTTPS in production) 
 - sameSite: 'Strict'

### Dependency Management 

	Core Dependencies
Package	Purpose
express	Web framework
mongoose	MongoDB interaction
bcryptjs	Password hashing
jsonwebtoken	JWT creation and validation
cookie-parser	Parses cookies, used for JWT auth
dotenv	Environment variables (.env file)
cors	Cross-origin requests handling
validator	Input sanitization and email checks


	Authentication Dependencies 

passport	Authentication framework
passport-google-oauth20	Google OAuth strategy

	Security Practices

1.	Package-lock.json tracks dependencies
2.	Don't use too many unnecessary libraries.
3.	Frequently perform npm audits.
4.	Use.gitignore to escape version control for node_modules.

### Lessons Learned
1.	Login Not Working
Problem:- The login was always failing, even with the right credentials.
Cause:- The root cause was that the select: false setting in the MongoDB schema was causing the user to be returned without the password field.
What I Tried:
•	Frontend submission double-checked
•	Console-logged query and answer
•	When I attempted to print the user fetched page, I discovered that there was no password. 
Solution:- I inserted it explicitly.In the login controller, select('+password').
Lesson: Make sure that, when necessary, fields in the schema that are designated with select: false are explicitly selected.

2.	Role-Based Access Bugs
Problem:- Regular users could take admin-only routes.
Cause:- VerifyToken only authorized users; it did not validate roles because middleware for role validation was absent.
Solution:- Made a requirement Middleware role.
Lesson: Authorization is just as important to security as authentication. Distinguish privilege boundaries at all times.

### More In general issues and lessons.
1.	Small syntax errors created a lot more issue than bigger problems which consumed most of my time.
2.	Jumping to conclusions for solutions of my errors without calculating its effect on other parts of code caused a lot of issue.

