import { asyncHandler } from "../utils/asyncHandler.js";
import { ApiError } from "../utils/ApiError.js";
import { UserDocument } from "../models/user.model.js";
import { NextFunction, Request } from "express";

//~ THIS MIDDLEWARE IS USUALLY USED FOR USER AND ADMIN ROUTES, GENERALLY NOT FOR AUTH ROUTE 

export const isAccountActive = asyncHandler(async (req: Request, _, next: NextFunction) => {
    //NOTE: This middleware should always Come after verify jwt Middleware 
    // First verify the jwt. And then verify whether account is active or not. 

    //user is made available in the request in verifyJWT middleware
    const user = req.user as UserDocument;

    if (!user || user.account_status !== 'active') {
        // If user is not defined or is not an admin, return 403 Forbidden
        throw new ApiError(403, "This account's status is not active");
    }

    next();
})