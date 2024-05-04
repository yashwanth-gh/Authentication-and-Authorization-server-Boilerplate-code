import { SessionOptions } from "express-session";
import { ObjectId } from "mongoose";

export type User = {
    _id: ObjectId; // Assuming ObjectId is a custom type or imported from a library
    fullName: string;
    email: string;
    createdAt: Date;
    updatedAt: Date;
    __v?: number;
}

export interface GoogleTokens{
    access_token:string;
    refresh_token:string;
    scope:string;
    expires_in:number;
    id_token:string;
}

export interface UserProfileData {
    id: string;
    email: string;
    verified_email: boolean;
    name: string;
    given_name: string;
    family_name: string;
    picture: string;
    locale: string;
}

export interface CustomSessionOptions extends SessionOptions {
    httpOnly: boolean;
    secure: boolean;
    maxAge: number;
}

export interface SessionUser {
    id: string;
    fullName: string;
    email: string;
}