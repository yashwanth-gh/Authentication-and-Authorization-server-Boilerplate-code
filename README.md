view the api here with postman documentation :
[click here](https://documenter.getpostman.com/view/31973819/2sA35Ba3tP)

# Authentication and Authorization Server Boilerplate Code

## Overview
This is the peroject i did on my own without any help from any tutorials. But i read some blogs and docs for better security measure in codebase.   
This project provides boilerplate backend API code for an authentication and authorization server. It offers API endpoints for both administrators and users, enabling secure access to resources. Authentication can be performed using Google OAuth or by traditional email/password authentication. Additionally, email verification is implemented using OTP (One-Time Password) for enhanced security.

## Features

- Secure API endpoints for administrators and users.
- Authentication options include Google OAuth and email/password.
- Email verification using OTP for added security.

## Getting Started

To get started with using this boilerplate code, follow these steps:

1. Clone the repository to your local machine.
2. Install the necessary dependencies by running `npm install`.
3. Set up your environment variables for configuring Google OAuth credentials and SMTP server details for email verification.
4. Run the server using `npm start`.
5. Access the API endpoints as needed for your application.

## Usage

### API Endpoints

Auth endpoints   
**POST `/signup`** : Register a new user.   
**POST `/admin/register`** : Register a new admin.    
**POST `/sendOTP`** : Send OTP for email verification.      
**POST `/verifyOTP`** : Verify email with OTP     
**POST `/signin`** : Sign in as a user.    
**POST `/admin/signin`** : Sign in as an admin.      
**GET `/google/login`** : Initiate Google OAuth login.    
**GET `/getGoogleUser`** : Get Google user details.    
**GET `/getCurrentUser`** : Get current user details.     
**GET `/refreshAccessToken`** : Refresh access token.    
**GET `/logout`** : Logout the current session.    
**POST `/sendResetPasswordLink`** : Send reset password link via email.    
**POST `/resetPassword`** : Reset password using reset token.    
**GET `/checkSession`** : Check user session status.    

User endpoints        
**POST `/changeCurrentPassword`** : Change current user password.    
**DELETE `/deleteAccount`** : Delete user account.    
**PATCH `/changeUserFullName`** : Change user's full name.    

Admin endpoints   
**GET `/viewAllPendingAdminRequests`** : View all pending admin requests.    
**PATCH `/approvePendingAdminRequests`** : Approve pending admin requests.    
**GET `/viewUsers`** : View all users.    
**GET `/viewUsersByAccountStatus`** : View users by account status.    
**PATCH `/changeUserAccountStatus`** : Change user account status.    

## Configuration

Before running the project, ensure you have set up the following configurations:

- **Google OAuth**: Obtain your client ID and client secret from the [Google Developer Console](https://console.developers.google.com/) and set them in the environment variables `GOOGLE_OAUTH_CLIENT_ID` and `GOOGLE_OAUTH_CLIENT_SECRET` respectively. Also, configure the redirect URI (`GOOGLE_OAUTH_REDIRECT_URI`) to match your setup.   
- **MongoDB**: Set your MongoDB connection URI in the environment variable `MONGO_URI`.   
- **Token Secrets and Expiry**: Set your access token secret (`ACCESS_TOKEN_SECRET`), refresh token secret (`REFRESH_TOKEN_SECRET`), reset password token secret (`RESET_PASSWORD_TOKEN_SECRET`), access token expiry time (`ACCESS_TOKEN_EXPIRY`), and reset password token expiry time (`RESET_PASSWORD_TOKEN_EXPIRY`).   
- **Nodemailer**: Configure your email sender address (`NODEMAILER_SENDER_EMAIL_ADDRESS`) and passkey (`NODEMAILER_SENDER_EMAIL_PASSKEY`) for sending emails.   
- **Session and Cookie**: Set your session name (`SESS_NAME`), session secret (`SESS_SECRET`), session expiry time (`SESS_EXPIRY`), and cookie expiry time (`COOKIE_EXPIRY`).   


## Contributing

Contributions are welcome! Feel free to open issues or pull requests for any improvements or bug fixes.

