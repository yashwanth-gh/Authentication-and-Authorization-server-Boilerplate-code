import jwt from "jsonwebtoken";
import { asyncHandler } from "../utils/asyncHandler.js";
import { ApiError } from "../utils/ApiError.js";
import User from "../models/user.model.js";
import { conf } from "../constants.js";
import { NextFunction, Request, RequestHandler } from "express";

export const verifyJWT = asyncHandler(async (req:Request, _ , next:NextFunction) => {

    /* 
    ^ --What does this middleware do?
    ^   1] Check if there is any token in the cookie received from client
    ^   2] If the token does not exists,
    ^       there may be a chance where cookie has reached its maxAge in browser 
    ^       so there may be no cookie received
    ^   3] If the cookie as reached its maxAge then send a 401 status code along with some data 
    ^       in response to specify cookie need to be generated again by login
    ^   4] If token is retreived from cookie now check if access token is expired or not
    ^       if access token has expired then send 401 status code and send some data to
    ^       specify that client need to make a request again to this server to refresh Access token
    ^   5] Also check if both access and refresh token are expired, if expired then you need
    ^       need to login again
    ^   6] Now check if received JWT access token is valid or not by jwt.verify() method bu decoding it
    ^   7] Now use the decoded access token to make a request to the DB to check if user data exists in DB
    ^   8] If user data does not exists then send 401 status code to tell invalid access token
    ^   9] if user exist then make it availabele to next middleware in this route
    ^   10] call the next()
    */

    // (1)
    const token = req.cookies?.accessToken
        || req.header("Authorization")?.replace("Bearer ", "");

    // (2) and (3)
    if (!token) {
        throw new ApiError(400, "Bad request : no cookie found");
    }

    // (4) (5) (6)
    let decodedToken: jwt.JwtPayload;

    try {
        decodedToken = jwt.verify(token, conf.accessTokenSecret) as jwt.JwtPayload;
    } catch (error) {
        if (error instanceof jwt.TokenExpiredError) {
            throw new ApiError(401, "Unauthorized : Access token expired");
        }else if(error instanceof jwt.JsonWebTokenError){
            throw new ApiError(400, "Bad request : Access token is INVALID");
        } else {
            // Handle other JWT errors if necessary
            throw new ApiError(400, "Bad request : Something is wrong with token received")
        }
    }

    // (7)
    const user = await User
        .findById(decodedToken?._id)
        .select(
            "-password -refreshToken -googleAuthInfo"
        );

    // (8)
    if(!user){
        throw new ApiError(404,"Not Found : User not found")
    }

    // (9)
    req.user = user;

    next();
})