import { Request, Response } from "express";
import { asyncHandler } from "../utils/asyncHandler.js";
import userModel, { UserDocument, UserInput } from "../models/user.model.js";
import { ApiResponse } from "../utils/ApiResponse.js";
import { ApiError } from "../utils/ApiError.js";
import { sendSuccessulAdminApprovedMail } from "../utils/nodemailer.js";
import { Types } from "mongoose";

interface UserDocumentArray extends Array<UserDocument> { };

export class AdminController {

    viewAllPendingAdminRequests = asyncHandler(async (req: Request, res: Response) => {

        const pendingAdminRequests: UserDocumentArray = await userModel.aggregate([
            {
                $match: {
                    "role.role_type": "admin",
                    "role.is_role_verified": false
                }
            },
            {
                $project: {
                    password: 0
                }
            }
        ]);

        if (!pendingAdminRequests) {
            return res.status(404).json({
                message: "No pending admin requests found"
            })
        }


        return res
            .status(200)
            .json(
                new ApiResponse(
                    200,
                    pendingAdminRequests,
                    "All pending admin requests fetched successfully"
                )
            )
    })

    approvePendingAdminRequest = asyncHandler(async (req: Request, res: Response) => {

        const { userId } = req.query;

        if (!userId) {
            throw new ApiError(400, "Bad request : User id is required")
        }

        // Convert userId to ObjectId type
        const objectIdUserId = new Types.ObjectId(userId as string);

        // Update the user's role if they are an admin and not already verified
        const user = await userModel.findOneAndUpdate(
            {
                _id: objectIdUserId,
                "role.role_type": "admin",
                "role.is_role_verified": false
            },
            { $set: { "role.is_role_verified": true, "account_status": "active" } },
            { new: true }
        ).select("-password") as UserDocument

        if (!user) {
            throw new ApiError(404, "User not found or already verified");
        }

        await sendSuccessulAdminApprovedMail(user);

        return res
            .status(200)
            .json(
                new ApiResponse(
                    200,
                    user,
                    "Admin request approved successfully"
                )
            )

    })

    viewAllUsers = asyncHandler(async (req: Request, res: Response) => {

        const users: UserDocumentArray = await userModel.find({ "role.role_type": "user" }).select("-password -refreshToken -googleAuthInfo");

        if (!users) {
            throw new ApiError(404, "No users found");
        }

        return res.status(200).json(
            new ApiResponse(
                200,
                users,
                "All users fetched successfully"
            )
        )
    })

    viewAllUsersByAccountStatus = asyncHandler(async (req: Request, res: Response) => {

        const accountStatus = req.query.accountStatus as string;

        if (!accountStatus) {
            throw new ApiError(400, "Bad request : Account status is required")
        }

        const users = await userModel.find(
            { "role.role_type": "user", "account_status": accountStatus })
            .select("-password -refreshToken -googleAuthInfo");

        if (!users) {
            throw new ApiError(404, "No users found");
        }

        return res
            .status(200)
            .json(
                new ApiResponse(
                    200,
                    users,
                    `All ${accountStatus} users fetched successfully`
                )
            )
    })

    changeUserAccountStatus = asyncHandler(async (req: Request, res: Response) => {

        const { userId } = req.query;
        const { accountStatus } = req.body;

        if (!userId || !accountStatus) {
            throw new ApiError(400, "Bad request : User id and account status are required")
        }

        // Convert userId to ObjectId type : not necessary
        const objectIdUserId = new Types.ObjectId(userId as string);

        const user = await userModel.findOneAndUpdate(
            { _id: objectIdUserId },
            { $set: { "account_status": accountStatus } },
            { new: true }
        ).select("-password -refreshToken -googleAuthInfo");

        if (!user) {
            throw new ApiError(404, "User not found");
        }

        return res.status(200).json(
            new ApiResponse(
                200,
                user,
                `User account status changed to ${user.account_status} successfully`
            )
        )
    })

    getCurrentAdmin = asyncHandler(async (req: Request, res: Response) => {
        const user = req.user as UserDocument;
        return res
            .status(200)
            .json(
                new ApiResponse(
                    200,
                    user,
                    "Current admin fetched successfully"
                )
            )
    })
}

const adminController = new AdminController();
export default adminController;