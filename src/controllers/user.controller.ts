import User from "../models/user.model.js";
import { ApiError } from "../utils/ApiError.js";
import { ApiResponse } from "../utils/ApiResponse.js";
import { asyncHandler } from "../utils/asyncHandler.js";
import { Request, Response } from "express";

import authenticationControllers from "./auth.controller.js";
import { conf } from "../constants.js";

export class UserControllers {

    changeCurrentPassword = asyncHandler(async (req: Request, res: Response) => {
        const { email, oldPassword, newPassword } = req.body;

        const user = await User.findById(req.user?._id);

        if (!user) {
            throw new ApiError(404, "Not Found : user not found")
        }

        const isPasswordCorrect = await user.isPasswordCorrect(oldPassword);

        if (!isPasswordCorrect) throw new ApiError(400, "Bad request : Invalid old password");

        user.password = newPassword;
        await user.save({ validateBeforeSave: false });

        const { accessToken: newAccessToken, refreshToken: newRefreshToken } = await authenticationControllers.generateAccessAndRefreshToken(user._id);

        const options = {
            httpOnly: true,
            secure: conf.nodeEnv === 'production',
            maxAge: parseInt(conf.cookiesExpiry)
        };

        return res
            .status(200)
            .cookie("accessToken", newAccessToken, options)
            .cookie("refreshToken", newRefreshToken, options)
            .json(new ApiResponse(200, {}, "Password changed"));
    })

    changeUserFullname = asyncHandler(async (req: Request, res: Response) => {
        // Receive request to chnage the user details
        // Check if user exists
        // change the details in mongoDB
        //generate new access token and refresh tokens

        const { fullName } = req.body;

        if (fullName.trim().length == 0) throw new ApiError(400, "Bad request : fullName is empty");

        const userData = await User.findById(req.user?._id).select("-refreshToken -password");

        if (!userData) throw new ApiError(404, "Not found : user not found");

        userData.fullName = fullName;
        await userData.save({ validateBeforeSave: false });

        const { accessToken: newAccessToken, refreshToken: newRefreshToken } = await authenticationControllers.generateAccessAndRefreshToken(userData._id);

        res.clearCookie("accessToken")
        res.clearCookie("refreshToken")


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
                    {
                        userData
                    },
                    "successfully updated full name"
                )
            )

    })

    deleteUserAccount = asyncHandler(async (req: Request, res: Response) => {
        const { password } = req.body;

        const userId = req.user?._id;

        // Step 1: Authenticate the user
        const user = await User.findById(userId);

        if (!user) {
            throw new ApiError(404, "Not found : User not found");
        }

        const isPasswordCorrect = await user.isPasswordCorrect(password);

        if (!isPasswordCorrect) {
            throw new ApiError(401, "Invalid password");
        }

        // Step 2: Delete the user document
        await User.findByIdAndDelete(userId);

        return res
            .status(200)
            .json(
                new ApiResponse(
                    200,
                    {},
                    "User accound deleted successfully!"
                )
            )
    })

}

const userControllers = new UserControllers();

export default userControllers;