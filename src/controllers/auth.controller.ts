import User from "../models/user.model.js";
import { getGoogleOAuthTokens, getGoogleUserProfile, isGoogleAccessTokenValid, refreshGoogleAccessToken } from "../services/user.service.js";
import { ApiError } from "../utils/ApiError.js";
import { ApiResponse } from "../utils/ApiResponse.js";
import { asyncHandler } from "../utils/asyncHandler.js";
import jwt from "jsonwebtoken";
import { Request, Response } from "express";
import { conf } from "../constants.js";
import UserVerificationModel from "../models/UserVerification.model.js";
import { sendAccountVerificationSuccessulMail, sendResetPasswordMail, sendVerificationMail, sendVerifyAdminMail } from "../utils/nodemailer.js";
import { hasOneMinutePassed, hasOtpExpired } from '../utils/otpHelper.js'
import resetPasswordModel from "../models/resetPassword.model.js";
import { generateResetPasswordToken } from "../utils/jwtHelper.js";

export class AuthenticationControllers {

    generateAccessAndRefreshToken = async (userId: string) => {
        /* This code is a function called generateAccessAndRefreshToken that takes a userId as a parameter.
      Inside the function, it first uses the User model to find a user with the given userId using the findById method. This is an asynchronous operation, so it uses the await keyword to wait for the result.
      Once the user is found, it calls the generateAccessToken and generateRefreshToken methods on the user object to generate an access token and a refresh token respectively.
      After that, it saves the user object with the save method. The {validateBeforeSave:false} option is passed to disable validation before saving the user object.
      Finally, it returns an object containing the access token and refresh token.
      Overall, this code retrieves a user by their ID, generates an access token and a refresh token for that user, saves the user object, and returns the tokens. */

        const user = await User.findById(userId);
        if (!user) throw new ApiError(404, "User not found");

        const accessToken = await user.generateAccessToken();
        const refreshToken = await user.generateRefreshToken();
        user.refreshToken = refreshToken;

        await user.save({ validateBeforeSave: false });

        return { accessToken, refreshToken };
    }

    AuthenticateWithGoogleOAuth = asyncHandler(async (req: Request, res: Response) => {
        /*
        Workflow:
        1. Get code from query string
        2. Get ID and access token By exchanging the Authorization code.
        3. Get the users Token. 
        4. Get the user's profile. 
        5. Create a new user By creating a session.
        6. Set the cookies. 
        7. Redirect to client.  
        */

        // 1. Get code from query string
        const code = req.query.code as string;

        // 2. Get ID and access token By exchanging the Authorization code.
        const googleOauthResponse = await getGoogleOAuthTokens({ code });


        // 3. Decode the ID token to obtain user details.
        const googleUserDetails: any = jwt.decode(googleOauthResponse.id_token);

        // 4. Check if the user already exists in your database.
        let user = await User.findOne({ email: googleUserDetails.email });

        if (user) throw new ApiError(409, "Conflict : user acoount already exists : overrite this with oauth");

        // 5. If the user does not exist, create a new user entry with the obtained Google user details.
        if (!user) {
            const currentTime = new Date().getTime();
            const expiryTimeMillisec = currentTime + googleOauthResponse.expires_in * 1000;

            user = await User.create({
                fullName: googleUserDetails.name,
                email: googleUserDetails.email,
                googleId: googleUserDetails.sub,
                profilePictureUrl: googleUserDetails.picture,
                googleAuthInfo: {
                    accessToken: googleOauthResponse.access_token,
                    refreshToken: googleOauthResponse.refresh_token,
                    expiresAt: new Date(expiryTimeMillisec), // Store expiry time as a Date object
                    scope: googleOauthResponse.scope
                },
                is_verified: true // Assume user is verified by google
            });
        }


        // 6. Generate access and refresh tokens for the user.
        const { accessToken, refreshToken } = await this.generateAccessAndRefreshToken(user._id);



        const options = {
            httpOnly: true,
            secure: conf.nodeEnv === 'production',
            maxAge: parseInt(conf.cookiesExpiry)
        };

        const origin = req.headers.origin || conf.corsOrigin;

        return res
            .status(200)
            .cookie("accessToken", accessToken, options)
            .cookie("refreshToken", refreshToken, options)
            .redirect(origin);

    })

    getGoogleUser = asyncHandler(async (req: Request, res: Response) => {

        let user = await User.findOne({ email: req.user?.email });
        if (!user) throw new ApiError(404, "User not found");

        if (!user.googleAuthInfo) throw new ApiError(400, "User not authenticated with google");

        let accessToken = user.googleAuthInfo?.accessToken;

        if (!isGoogleAccessTokenValid(user.googleAuthInfo.expiresAt)) {
            //Access token is expired 
            console.log("Access token is expired");
            //refresh the access token

            let googleRefreshToken = user.googleAuthInfo.refreshToken;
            if (!googleRefreshToken) throw new ApiError(400, " No refresh token found in DATABASE");

            accessToken = await refreshGoogleAccessToken(googleRefreshToken, user._id)

            console.log("new access token", accessToken);
        } else {
            console.log("Access token is valid");
        }


        const userDetails = await getGoogleUserProfile(accessToken);

        return res
            .status(200)
            .json(
                new ApiResponse(200, { userDetails }, "user details")
            );
    })

    createNewUserAccount = asyncHandler(async (req: Request, res: Response) => {
        /* 
        Here he handled the traditional email password login. 
        Generate a Access and refresh token For the traditional method.
        Save the user data In the session and also send it as a cookie. 
        */

        /*
        ^STEPS FOR THIS CONTROLLER :
        1. Extract fullName, email, and password from the request body.
        2. Check if a user with the provided email already exists in the database.
        3. If a user with the email exists:
            - Throw a 409 (Conflict) ApiError indicating that the user already exists.
        4. If no user with the email exists:
            - Create a new user in the database using the User model, with the provided fullName, email, and password.
            - Get the created user's details (excluding password and refreshToken) from the database.
            - If the created user is not found, throw a 500 ApiError.
        5. Return a JSON response with a 200 status code, containing:
            - An ApiResponse object with a success message and the details of the created user (excluding password and refreshToken). 
        */

        const { fullName, email, password } = req.body;

        const existedUser = await User.findOne({ email });

        if (existedUser) {
            throw new ApiError(409, "User with username or email already exists");
        }

        const user = await User.create({
            fullName,
            email,
            password,
            is_verified: false,
            account_status: "pending",
            role: {
                role_type: "user",
                is_role_verified: false
            }
        });

        const createdUser = await User.findById(user._id).select(
            "-password -refreshToken"
        );

        if (!createdUser) throw new ApiError(500, "User not created")


        return res
            .status(201)
            .json(
                new ApiResponse(201, createdUser, "user created")
            );
    })

    loginExistingUser = asyncHandler(async (req: Request, res: Response) => {
        const { email, password } = req.body;

        const user = await User.findOne({ email });

        if (!user) {
            throw new ApiError(404, "User not found");
        }

        //Don't allow admin to use this endpoint this endpoint is only for user
        if (user.role.role_type !== "user") {
            throw new ApiError(401, "Only users can use this endpoint,if you are admin use different endpoint to login");
        }

        //also check if user account status is active don't allow "pending", "suspended" and "blocked"
        if (user.account_status !== "active") {
            throw new ApiError(401, "User account status is not active, Please check user account status using different endpoint");
        }

        //also check if user email is verified or not
        if (!user.is_email_verified) {
            throw new ApiError(401, "User email is not verified, Please verify user email by sending OTP");
        }

        //also check if user role is verified or not
        if (!user.role.is_role_verified) {
            throw new ApiError(401, "User role is not verified, Please verify user role by sending OTP");
        }

        const isPasswordCorrect = await user.isPasswordCorrect(password);

        if (!isPasswordCorrect) {
            throw new ApiError(403, "Invalid password or password does not exist try othe way of signin");
        }

        const { accessToken, refreshToken } = await this.generateAccessAndRefreshToken(user._id);

        const loggedInUser = await User.findById(user._id).select(
            "-password -refreshToken -googleAuthInfo"
        );

        if (!loggedInUser) {
            throw new ApiError(500, "User not found")
        }

        const sessionUser = { id: user._id, fullName: user.fullName, email: user.email };
        req.session.user = sessionUser;

        const options = {
            httpOnly: true,
            secure: conf.nodeEnv === 'production',
            maxAge: parseInt(conf.cookiesExpiry)
        };

        return res
            .status(200)
            .cookie("accessToken", accessToken, options)
            .cookie("refreshToken", refreshToken, options)
            .json(
                new ApiResponse(
                    200,
                    loggedInUser,
                    "User logged in successfully"
                )
            );

    });

    createNewAdminAccount = asyncHandler(async (req: Request, res: Response) => {
        const { fullName, email, password } = req.body;

        const existedUser = await User.findOne({ email });

        if (existedUser) {
            throw new ApiError(409, "User with username or email already exists");
        }

        const user = await User.create({
            fullName,
            email,
            password,
            is_verified: false,
            role: {
                role_type: "admin",
                is_role_verified: false
            },
            account_status: "pending"
        });

        const createdUser = await User.findById(user._id).select(
            "-password -refreshToken"
        );

        if (!createdUser) throw new ApiError(500, "User not created")

        return res
            .status(201)
            .json(
                new ApiResponse(201, createdUser, "user created")
            );
    })

    loginExistingAdmin = asyncHandler(async (req: Request, res: Response) => {
        const { email, password } = req.body;

        const user = await User.findOne({ email });

        if (!user) {
            throw new ApiError(404, "Admin not found");
        }

        if (user.role.role_type !== 'admin') {
            throw new ApiError(401, "This Api endpoint is for admin login only, users should use different endpoint")
        }

        //also check if user email is verified or not
        if (!user.is_email_verified) {
            throw new ApiError(401, "Admin email is not verified, Please verify admin email by sending OTP");
        }

        if (user.role.role_type === 'admin' && user.role.is_role_verified === false) {
            throw new ApiError(401, "Admin account is not verified yet, please wait till account is verified!");
        }

        //also check if user account status is active don't allow "pending", "suspended" and "blocked"
        if (user.account_status !== "active") {
            throw new ApiError(401, "Admin account status is not active, Please check this account's status using different endpoint");
        }

        const isPasswordCorrect = await user.isPasswordCorrect(password);

        if (!isPasswordCorrect) {
            throw new ApiError(403, "Invalid password or password does not exist try othe way of signin");
        }

        const { accessToken, refreshToken } = await this.generateAccessAndRefreshToken(user._id);

        const loggedInUser = await User.findById(user._id).select(
            "-password -refreshToken -googleAuthInfo"
        );

        if (!loggedInUser) {
            throw new ApiError(500, "Admin not found")
        }

        const options = {
            httpOnly: true,
            secure: conf.nodeEnv === 'production',
            maxAge: parseInt(conf.cookiesExpiry)
        };

        return res
            .status(200)
            .cookie("accessToken", accessToken, options)
            .cookie("refreshToken", refreshToken, options)
            .json(
                new ApiResponse(
                    200,
                    loggedInUser,
                    "Admin logged in successfully"
                )
            );

    });

    sendOtpToMail = asyncHandler(async (req: Request, res: Response) => {

        const { email } = req.body;

        const user = await User.findOne({ email });

        if (!user) {
            throw new ApiError(404, "Not fount : Email not found");
        }

        if (user.is_email_verified) {
            throw new ApiError(400, "Bad request : User is already verified")
        }

        const oldOtdData = await UserVerificationModel.findOne({ user_id: user._id });

        if (oldOtdData) {
            console.log(Number(oldOtdData.timestamp))
            const canSendOtp: boolean = hasOneMinutePassed(Number(oldOtdData.timestamp));
            if (!canSendOtp) {
                throw new ApiError(400, "Try after sometime!")
            }
        }
        //& This is the function which sends the OTP to user's Mail address and return the 6 digit OTP
        const VerificationCode = sendVerificationMail(user);

        const cDate = new Date();

        await UserVerificationModel.findOneAndUpdate(
            { user_id: user._id },
            { otp: VerificationCode, timestamp: new Date(cDate.getTime()), codeType: "Verification-code" },
            { upsert: true, new: true, setDefaultsOnInsert: true }
        )

        return res
            .status(200)
            .json(
                new ApiResponse(
                    200,
                    {},
                    "Verification mail succesfully sent!")
            )

    })

    verifyOTP = asyncHandler(async (req: Request, res: Response) => {
        const { email, otp } = req.body;

        if (otp.length != 6) {
            throw new ApiError(401, "invalid OTP, OTP should be 6 digits")
        }

        // Aggregation pipelines can be used like below, but for this I think this is unnecessary complicated. 
        /*  // Aggregation pipeline to join User and UserVerification collections
            const otpInfo = await User.aggregate([
                // Match user by email
                { $match: { email } },
                // Lookup UserVerification documents
                {
                    $lookup: {
                        from: 'userverifications', // Name of the UserVerification collection
                        localField: '_id',
                        foreignField: 'user_id',
                        as: 'verificationInfo'
                    }
                },
                // Unwind the verificationInfo array (as it's a one-to-one relationship)
                { $unwind: '$verificationInfo' },
                // Project to only return the OTP
                { $project: { _id: 0, otp: '$verificationInfo.otp' } }
            ]); */

        const user = await User.findOne({ email });
        if (!user) {
            throw new ApiError(404, "User not found")
        }

        const userVerificationDetails = await UserVerificationModel.findOne({ user_id: user._id });
        if (!userVerificationDetails) {
            throw new ApiError(404, "OTP not nound : Not sent any otp to mail")
        }

        const otpExpired: boolean = hasOtpExpired(Number(userVerificationDetails.timestamp));
        if (otpExpired) {
            throw new ApiError(401, "Unauthorised : OTP has expired!")
        }

        const isOtpMatching = userVerificationDetails.otp === Number(otp)

        if (!isOtpMatching) {
            throw new ApiError(401, "Unauthorized: OTP does not match")
        }

        user.is_email_verified = true;

        // check the role of registered user and make decision accordingly
        if (user.role.role_type === 'user') {
            user.role.is_role_verified = true;
            user.account_status = "active";
            await sendAccountVerificationSuccessulMail(user);
        }
        if (user.role.role_type === 'admin' && user.role.is_role_verified === false) {
            await sendVerifyAdminMail(user);
        }
        await user.save({ validateBeforeSave: false });

        await UserVerificationModel.deleteOne({ user_id: user._id })

        return res
            .status(200)
            .json(
                new ApiResponse(200,
                    {},
                    "User account verified successully"
                )
            )

    })

    logout = asyncHandler(async (req: Request, res: Response) => {

        const userData = await User.findByIdAndUpdate(
            req.user?._id,
            {
                $unset: {
                    refreshToken: 1, // this removes the field from document
                },
            },
            {
                new: true,
            }
        );

        req.session.destroy((err) => {
            //delete session data from store, using sessionID in cookie
            if (err) throw new ApiError(500, "Internal Server Error : Something went wrong");
        });


        const options = {
            httpOnly: true,
            secure: conf.nodeEnv === 'production',
        };

        return res
            .status(200)
            .clearCookie("accessToken", options)
            .clearCookie("refreshToken", options)
            .clearCookie(conf.sessionName)
            .json(new ApiResponse(200, {}, "User logged out succesfully!"));

    })

    refreshAccessToken = asyncHandler(async (req: Request, res: Response) => {

        const incomingRefreshToken = req.cookies.refreshToken || req.body.refreshToken;

        if (!incomingRefreshToken) {
            throw new ApiError(400, "Bad Request : No Refresh token in cookie");
        }

        let decodedRefreshToken: jwt.JwtPayload;

        try {
            decodedRefreshToken = jwt.verify(incomingRefreshToken, conf.refreshTokenSecret) as jwt.JwtPayload;
        } catch (error) {
            if (error instanceof jwt.TokenExpiredError) {
                throw new ApiError(401, "Unauthorized : Both Access and Refresh token expired : login again");
            } else if (error instanceof jwt.JsonWebTokenError) {
                throw new ApiError(401, "Unauthorized : Refresh token is INVALID");
            } else {
                // Handle other JWT errors if necessary
                throw new ApiError(400, "Bad request : Something is wrong with token received")
            }
        }

        const user = await User
            .findById(decodedRefreshToken?._id)
            .select(
                "-password"
            );

        if (!user) {
            throw new ApiError(404, "Not Found : User not found")
        }

        if (incomingRefreshToken != user.refreshToken) {
            throw new ApiError(401, 'Unauthorized : The provided refresh token is invalid');
        }

        const { accessToken: newAccessToken, refreshToken: newRefreshToken } = await this.generateAccessAndRefreshToken(user._id);

        const options = {
            httpOnly: true,
            secure: conf.nodeEnv === 'production',
            maxAge: parseInt(conf.cookiesExpiry)
        };

        return res
            .status(200)
            .cookie("accessToken", newAccessToken, options)
            .cookie("refreshToken", newRefreshToken, options)
            .json(
                new ApiResponse(
                    200,
                    {},
                    "Access token and refresh token refreshed"
                )
            )

    })

    getCurrentUser = asyncHandler(async (req: Request, res: Response) => {
        // const userData = await User.findById(req.user?._id).select("-password -refreshToken")
        const userData = req.user;
        if (!userData) {
            throw new ApiError(500, "Server Error");
        }
        return res
            .status(200)
            .json(
                new ApiResponse(200, userData, "current user data fetched successfully")
            );
    })

    sendMailToResetPassword = asyncHandler(async (req: Request, res: Response) => {
        const { email } = req.body;

        const user = await User.findOne({ email });

        if (!user) {
            /* 
            Thinking why there is no error thrown here. i read the below code in some article so i tried it.
            " When they submit the email address, this will trigger the back-end to check if that email exists in the database. Even if the email doesn’t exist, we’ll show a message that says the email has been sent successfully. That way we don’t give attackers any indication that they should try a different email address. "
            */
            return res
                .status(200)
                .json(
                    new ApiResponse(
                        200,
                        {},
                        "Reset link sent ;)"
                    )
                )
        }

        const oldResetPasswordData = await resetPasswordModel.findOne({ user_id: user._id });

        if (oldResetPasswordData) {
            const canSendMail: boolean = hasOneMinutePassed(Number(oldResetPasswordData.timestamp));
            if (!canSendMail) {
                throw new ApiError(400, "Try after sometime!")
            }
        }

        //Generating reset password token to send as a parameter in a link to resent the password
        const resetToken = generateResetPasswordToken(user._id);

        //Save new document or update the existing document to new reset token
        const cDate = new Date();
        const resetData = await resetPasswordModel.findOneAndUpdate(
            { user_id: user._id },
            { resetToken: resetToken, timestamp: new Date(cDate.getTime()) },
            { upsert: true, new: true, setDefaultsOnInsert: true }
        )

        if (!resetData) {
            throw new ApiError(500, "Internal server error : Reset token not saved in database")
        }
        //sent the reset link to the user email address only if the reset token is saved successfully in the database
        await sendResetPasswordMail(user, resetToken);

        return res
            .status(200)
            .json(
                new ApiResponse(
                    200,
                    {},
                    "OTP sent to your mail successfully"
                )
            )
    })

    resetPasswordWithToken = asyncHandler(async (req: Request, res: Response) => {
        const { password } = req.body;
        const { resetToken } = req.query;

        // Check if the JWT is expired or valid. This will automatically throw error if invalid. 
        const decodedResetTokenData = await jwt.verify(resetToken as string, conf.resetPasswordTokenSecret) as jwt.JwtPayload;

        if (!decodedResetTokenData) throw new ApiError(400, "Bad request : Invalid reset token")

        // Get user Id. If the token is valid 
        const decodedUserId = decodedResetTokenData.user_id;

        //Check if there is a document existing In reset password model. 
        const resetPasswordData = await resetPasswordModel.findOne({ user_id: decodedUserId });

        if (!resetPasswordData) {
            throw new ApiError(404, "Not Found : No Token Data found in DB")
        }

        const user = await User.findById(resetPasswordData.user_id);

        if (!user) {
            throw new ApiError(404, "Not found : User not found")
        }

        user.password = password;
        await user.save({ validateBeforeSave: false });

        await resetPasswordModel.deleteOne({ user_id: user._id });

        return res
            .status(200)
            .json(
                new ApiResponse(
                    200,
                    {},
                    "Password changed successfully"
                )
            )
    })

    checkSessionforAuth = asyncHandler(async (req: Request, res: Response) => {
        const userSession = req.session.user;

        if (!userSession) {
            throw new ApiError(401, "Unauthorized : Session expired login again")
        }

        return res
            .status(200)
            .json(
                new ApiResponse(
                    200,
                    {},
                    "Session is valid"
                )
            )
    })
}

const authenticationControllers = new AuthenticationControllers();

export default authenticationControllers;