import { asyncHandler } from "../utils/asyncHandler.js";
import { ApiError } from "../utils/ApiError.js";
import { UserDocument } from "../models/user.model.js";
import { NextFunction, Request } from "express";

//~ THIS MIDDLEWARE IS USED FOR ADMIN ROUTES

export const verifyAdmin = asyncHandler(async (req: Request, _, next: NextFunction) => {
    //NOTE: This middleware should always Come after verify jwt Middleware 
    // First verify the jwt. And then verify whether Person is admin. 

    //user is made available in the request in verifyJWT middleware
    const user = req.user as UserDocument;

    if (!user || user.role.role_type !== 'admin') {
        // If user is not defined or is not an admin, return 403 Forbidden
        throw new ApiError(403, "Admin access required");
    }

    // Check if the admin's role is verified
    if (!user.role.is_role_verified) {
        throw new ApiError(403, "Admin role not verified");
    }

    next();
})