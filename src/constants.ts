export const DB_NAME = "Authentication"

// stringfying variable from your .env
export const conf = {
    googleClientId:String(process.env.GOOGLE_OAUTH_CLIENT_ID),
    googleClientSecret:String(process.env.GOOGLE_OAUTH_CLIENT_SECRET),
    googleOauthRedirectUri:String(process.env.GOOGLE_OAUTH_REDIRECT_URI),
    googleOauthTokenUri:String(process.env.GOOGLE_OAUTH_TOKEN_URI),
    corsOrigin:String(process.env.CORS_ORIGIN),
    mongoURI: String(process.env.MONGO_URI),
    nodeEnv:String(process.env.NODE_ENV),
    accessTokenSecret: String(process.env.ACCESS_TOKEN_SECRET),
    refreshTokenSecret: String(process.env.REFRESH_TOKEN_SECRET),
    accessTokenExpiry: String(process.env.ACCESS_TOKEN_EXPIRY),
    refreshTokenExpiry: String(process.env.REFRESH_TOKEN_EXPIRY),
    resetPasswordTokenSecret: String(process.env.RESET_PASSWORD_TOKEN_SECRET),
    resetPasswordTokenExpiry: String(process.env.RESET_PASSWORD_TOKEN_EXPIRY),
    nodemailerSenderMailAddress :  String(process.env.NODEMAILER_SENDER_EMAIL_ADDRESS),
    nodemailerSenderMailPasskey :  String(process.env.NODEMAILER_SENDER_EMAIL_PASSKEY),
    sessionName :  String(process.env.SESS_NAME),
    sessionSecret :  String(process.env.SESS_SECRET),
    sessionExpiry :String(process.env.SESS_EXPIRY),
    cookiesExpiry :String(process.env.COOKIE_EXPIRY)
}