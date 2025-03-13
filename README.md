## Setting Up the Repository
1. Clone the Repository:
Clone the repository to your local machine:
git clone cd your-repository

2. Install dependencies. 
Ensuring that Node.js and npm are installed. Then, using the command below to install the dependencies:
npm install 

3. Set Up Environment Variables:
Create a .env file in the root directory and add your environment variables:

JWT_SECRET=your_jwt_secret
GOOGLE_CLIENT_ID=your_google_client_id
GOOGLE_CLIENT_SECRET=your_google_client_secret

4. Running the Application: Run the server with:
Your application is now available at http://localhost:3000.

## Authentication Mechanisms

1.	Local Authentication (Username and Password): 
User registration needs a username and password. The password is protected using bcrypt hashing. 
Login: Users enter their credentials. If valid, a JWT is generated and kept as a HttpOnly cookie to manage sessions. 
2.	Google OAuth Authentication: Log in with Google: 
 Users can login via Google authentication. On successful login, access and refresh tokens are generated and kept as HttpOnly cookies. 
JWT Tokens: Access and refresh tokens are given to ensure the security of user sessions.
3.	Session Management: 
The access token lasts 15 minutes and is kept in a HttpOnly cookie to avoid XSS attacks.
Refresh Token: The refresh token lasts 7 days and may be used to produce new access tokens once they have expired. It is also set as a HttpOnly cookie. 
Cookies are tagged Secure and SameSite=Strict to prevent a cross-site fraud. 


## Role-Based Access Control (RBAC)
1. User Roles:
    User: Can access the user dashboard.
    Permissions: User's own data and dashboard.
2. Admin Roles: 
    Admin: Can access the admin dashboard.
    Permissions: Full admin control.

## Lessons Learned
There were alot of challanges due to doing this for the first time , everything got resolved going over labs and youtube videos. but the major problems i had and spent a lot of my time are
1. Token Management: It was challenging to securely store JWT tokens in HttpOnly cookies, but it provides strong protection against XSS attacks. 
2. Role-based Access: It was challenging to handle user roles and ensure they could only access permitted resources, so a lot of planning and testing was involved.
# Solution:
1. Secure Cookie Storage: Through the HttpOnly and Secure cookie flags, we ensured that tokens are out of reach for and cannot be tampered with by JavaScript, hence preventing potential attacks.
2. Role-Based Middleware: The role validation in the requireRole middleware successfully prevented unauthorized access to sensitive parts of the application.


Reflection Points 

1. I decide to use both password-based login and Google SSO. Password login is secure since I will hash the passwords, and Google SSO is faster and easier for users. This allows consumers to select what works best for them, and both approaches are secure. Google enhances security with features like two-factor authentication.

2. I created two roles: "admin" and "user"I used middleware functions like verifyToken and requireRole to limit access to protected routes based on the user's role." The "admin" could have access to routes like /admin, but the "user" may have access to routes like /profile and /dashboard. The challenge was to achieve the right balance between user convenience and security. By establishing only two roles, I kept things simple while yet ensuring sensitive data was kept safe. Adding new roles might increase complexity but might not provide major benefits for this project. I designed a simple solution that was both secure and user-friendly.

3. I chose to store tokens in HttpOnly cookies for security reasons. This makes sure that JavaScript cannot access the tokens, lowering the risk of XSS attacks. The cookies are also marked as Secure in production, thus guaranteeing they are only sent via HTTPS connections. The access token has a 15-minute expiration duration, which reduces the abuse window in case it is hacked. It's a solid balance between usability and security since it reduces the attack window as much as possible while also preventing users from remaining signed in for too long. The refresh token has been setup to expire after 7 days, allowing users to enjoy an effortless experience without the need for frequent re-authentication. To avoid CSRF attacks, I assured that the access and refresh tokens were securely stored in HttpOnly cookies with a SameSite attribute value of Strict. Overall, I feel that this approach provides enough security without losing too much user experience. The most challenging part was finding the right balance between security features (such as short-term access tokens) and a decent user experience (with refresh tokens to reduce constant login issues).

4. To secure user sessions, I focused on the following essential steps: 
Secure Cookies: To prevent attacks like CSRF and session hijacking, I added the Secure, HttpOnly, and SameSite attributes to cookies. 
Session Timeout: Access tokens last 15 minutes, whereas refresh tokens last 7 days, reducing the possibility for window improper use. 
Rate Limitation: I applied rate limitation to avoid brute-force assaults by temporarily suspending accounts after a number of failed login attempts. 
Session Fixation: To prevent session fixation attacks, I re-created session IDs after successful login.

5. To verify the authentication process, I used Postman to: 
Validate login and logout through POST requests with valid and inaccurate credentials. 
Verify that the JWT token generation for protected routes was successful.  Test role-based access by checking that users can access their respective dashboards. Test the refresh token endpoint to ensure that new tokens were issued appropriately.
