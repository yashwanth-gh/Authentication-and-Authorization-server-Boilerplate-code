import jwt from "jsonwebtoken";
import { conf } from "../constants.js";

export const generateResetPasswordToken =  (userId:string):string => {
    return jwt.sign(
        {
            user_id: userId
        },
        conf.resetPasswordTokenSecret,
        {
            expiresIn: conf.resetPasswordTokenExpiry
        });
}