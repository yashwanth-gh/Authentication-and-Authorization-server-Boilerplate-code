import nodemailer from 'nodemailer'
import { conf } from '../constants.js';
import path from 'path';
import fs from 'fs';
import { ApiError } from './ApiError.js';
import { UserDocument } from '../models/user.model.js';

// Create a transporter object using SMTP transport
const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user: conf.nodemailerSenderMailAddress,
        pass: conf.nodemailerSenderMailPasskey
    }
});

export const sendVerificationMail = (user: UserDocument) => {
    const mailTemplatePath = path.resolve("public", "verificationMail.html");
    const mailBodyTemplate = fs.readFileSync(mailTemplatePath, "utf-8");
    const VerificationCode = Math.floor(Math.random() * 900000) + 100000;
    const finalEmailTemplate = mailBodyTemplate
        .replaceAll("{{platformName}}", "<Company_name>")
        .replaceAll("{{userName}}", user.fullName)
        .replaceAll("{{senderName}}", "Yashwanth B M")
        .replace("{{OTP}}", VerificationCode.toString());

    const data = {
        from: conf.nodemailerSenderMailAddress,
        to: user.email,
        subject: "Verify your account",
        html: finalEmailTemplate,
    }

    try {
        transporter.sendMail(data, (err, info) => {
            if (err) {
                console.log(err);
            } else {
                console.log("mail sent!");
            }
        });
    } catch (error) {
        throw new ApiError(500, "Server error : Nodemailer sendmail error")
    }

    return VerificationCode;
}
export const sendResetPasswordMail = (user: UserDocument, resetToken: string): void => {
    const resetPasswordLink = `${conf.corsOrigin}/resetPassword?resetToken=${resetToken}`;
    const mailTemplatePath = path.resolve("public", "forgotPassword.html");
    const mailBodyTemplate = fs.readFileSync(mailTemplatePath, "utf-8");
    const finalEmailTemplate = mailBodyTemplate
        .replaceAll("{{userName}}", user.fullName)
        .replaceAll("{{senderName}}", "Yashwanth B M")
        .replace("{{resetLink}}", resetPasswordLink);

    const data = {
        from: conf.nodemailerSenderMailAddress,
        to: user.email,
        subject: "Reset Your Password",
        html: finalEmailTemplate,
    }

    try {
        transporter.sendMail(data, (err, info) => {
            if (err) {
                console.log(err);
            } else {
                console.log("mail sent!");
            }
        });
    } catch (error) {
        throw new ApiError(500, "Server error : Nodemailer sendmail error")
    }
}
export const sendVerifyAdminMail = (user: UserDocument): void => {

    const mailTemplatePath = path.resolve("public", "verifyNewAdmin.html");
    const mailBodyTemplate = fs.readFileSync(mailTemplatePath, "utf-8");
    const finalEmailTemplate = mailBodyTemplate
        .replaceAll("{{platformName}}", "<Company_name>")
        .replaceAll("{{newAdminName}}", user.fullName)
        .replace("{{newAdminEmail}}", user.email)
        .replace("{{senderName}}", "Yashwanth B M");

    const data = {
        from: conf.nodemailerSenderMailAddress,
        to: user.email,
        subject: "Verify New Admin",
        html: finalEmailTemplate,
    }

    try {
        transporter.sendMail(data, (err, info) => {
            if (err) {
                console.log(err);
            } else {
                console.log("mail sent!");
            }
        });
    } catch (error) {
        throw new ApiError(500, "Server error : Nodemailer sendmail error")
    }
}
export const sendAccountVerificationSuccessulMail = (user: UserDocument): void => {

    const mailTemplatePath = path.resolve("public", "accountSuccess.html");
    const mailBodyTemplate = fs.readFileSync(mailTemplatePath, "utf-8");
    const finalEmailTemplate = mailBodyTemplate
        .replaceAll("{{platformName}}", "<Company_name>")
        .replaceAll("{{userName}}", user.fullName)
        .replace("{{senderName}}", "Yashwanth B M");

    const data = {
        from: conf.nodemailerSenderMailAddress,
        to: user.email,
        subject: "Welcome User",
        html: finalEmailTemplate,
    }

    try {
        transporter.sendMail(data, (err, info) => {
            if (err) {
                console.log(err);
            } else {
                console.log("mail sent!");
            }
        });
    } catch (error) {
        throw new ApiError(500, "Server error : Nodemailer sendmail error")
    }
}
export const sendSuccessulAdminApprovedMail = (user: UserDocument): void => {

    const mailTemplatePath = path.resolve("public", "approvedAdminRequest.html");
    const mailBodyTemplate = fs.readFileSync(mailTemplatePath, "utf-8");
    const finalEmailTemplate = mailBodyTemplate
        .replaceAll("{{platformName}}", "<Company_name>")
        .replaceAll("{{userName}}", user.fullName)
        .replace("{{senderName}}", "Yashwanth B M");

    const data = {
        from: conf.nodemailerSenderMailAddress,
        to: user.email,
        subject: "Welcome Admin",
        html: finalEmailTemplate,
    }

    try {
        transporter.sendMail(data, (err, info) => {
            if (err) {
                console.log(err);
            } else {
                console.log("mail sent!");
            }
        });
    } catch (error) {
        throw new ApiError(500, "Server error : Nodemailer sendmail error")
    }
}

