import mongoose, { Document } from "mongoose";
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import { conf } from "../constants.js";

export interface GoogleAuthInfo {
    expiresAt: Date;
    accessToken: string;
    refreshToken?: string;
    scope: string;
}
export interface UserInput {
    fullName: string;
    email: string;
    password?: string; // Password becomes optional for Google OAuth users
    refreshToken?: string;
    googleId?: string; // New field to store Google User ID
    profilePictureUrl?: string; // New field to store profile picture URL
    googleAuthInfo?: GoogleAuthInfo; // New field to store Google OAuth info
    role: {
        role_type: "admin" | "user";
        is_role_verified: boolean;
    };
    is_email_verified: boolean;
    account_status: "active" | "pending" | "suspended" | "blocked";
}

export interface UserDocument extends UserInput, Document, Methods {
    createdAt: Date;
    updatedAt: Date;
}

interface Methods {
    isPasswordCorrect(password: string): Promise<boolean>;
    generateAccessToken(): string;
    generateRefreshToken(): string;
}

const userSchema = new mongoose.Schema<UserDocument>(
    {
        fullName: {
            type: String,
            required: true,
            trim: true,
            index: true
        },
        email: {
            type: String,
            required: true,
            unique: true,
            lowercase: true,
            trim: true,
            index: true
        },
        password: {
            type: String,
            required: false // Password becomes optional for Google OAuth users
        },
        refreshToken: {
            type: String
        },
        googleId: {
            type: String // New field to store Google User ID
        },
        profilePictureUrl: {
            type: String // New field to store profile picture URL
        },
        googleAuthInfo: {
            type: Object // Store Google OAuth info as an object
        },
        role: {
            role_type: {
                type: String,
                enum: ["admin", "user"],
                default: "user"
            },
            is_role_verified: {
                type: Boolean,
                default: false
            }
        },
        is_email_verified: {
            type: Boolean,
            default: false,
            required: true
        },
        account_status:{
            type: String,
            enum: ["active", "pending", "suspended", "blocked"],
            default: "pending",
            required:true
        }
    },
    {
        timestamps: true
    }
)

userSchema.pre<UserDocument>("save", async function (next) {
    if (!this.isModified("password") || !this.password) return next();
    this.password = await bcrypt.hash(this.password, 10);
    return next();
})

userSchema.methods.isPasswordCorrect = async function (password: string): Promise<boolean> {
    return await bcrypt.compare(password, this.password).catch(err => false)
}


userSchema.methods.generateAccessToken = function (): string {
    return jwt.sign(
        {
            _id: this._id,
            email: this.email,
            fullName: this.fullName,
            role: this.role
        },
        conf.accessTokenSecret,
        {
            expiresIn: conf.accessTokenExpiry
        }
    )
};


userSchema.methods.generateRefreshToken = function (): string {
    return jwt.sign(
        {
            _id: this._id,
        },
        conf.refreshTokenSecret,
        {
            expiresIn: conf.refreshTokenExpiry
        }
    )
};

export default mongoose.model<UserDocument>("User", userSchema)