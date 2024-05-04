import axios from "axios";
import { conf } from "../constants.js";
import qs from "qs";
import { log } from "console";
import { ApiError } from "../utils/ApiError.js";
import { GoogleTokens, UserProfileData } from "../types/custom/index.js";
import User from "../models/user.model.js";
import { handleAxiosError } from "../utils/handleAxiosErrors.js";



export async function getGoogleOAuthTokens({ code }: { code: string }): Promise<GoogleTokens> {
    const uri = conf.googleOauthTokenUri;
    const values = {
        code,
        client_id: conf.googleClientId,
        client_secret: conf.googleClientSecret,
        grant_type: "authorization_code",
        redirect_uri: conf.googleOauthRedirectUri
    }
    // console.log(uri)
    // console.log(values)
    try {
        const response = await axios.post<GoogleTokens>(uri, qs.stringify(values),
            {
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded',
                }
            })

        return response.data;
    } catch (error) {
        console.log("ERROR :: getGoogleOAuthTokens :: Failed to fetch google oauth tokens", error);
        handleAxiosError(error, "Failed to fetch google google oauth tokens")
    }
}

export async function getGoogleUserProfile(accessToken: string): Promise<UserProfileData> {
    const uri = 'https://www.googleapis.com/oauth2/v2/userinfo';
    try {
        const response = await axios.get<UserProfileData>(uri,
            {
                headers: {
                    Authorization: `Bearer ${accessToken}`,
                }
            })
        return response.data;
    } catch (error) {
        console.log("ERROR :: getGoogleUserProfile :: Failed to fetch google user profile", error);
        handleAxiosError(error, "Failed to fetch google user profile")
    }
}

export function isGoogleAccessTokenValid(expires_at: Date): boolean {
    // check USER EXPIRY TIME IN DB TO CHECK IF at IS EXPIRED OR ABOUT TO BE EXPIRED IN 5 MINUTES
    const currentTime = new Date().getTime();
    const expireTime = expires_at.getTime();
    const diffeenceTime = expireTime - currentTime;
    const timeInMinutes = diffeenceTime / (1000 * 60);

    // console.log("remaining time for access token to expire in min", timeInMinutes)

    if (expireTime <= currentTime) {
        // Token is expired
        return false;
    }
    if (timeInMinutes < 5) {
        // Token is about to expire (less than 5 minutes left), consider it invalid
        return false;
    }
    // Token is valid
    return true;
}

export async function refreshGoogleAccessToken(refreshToken: string, userId: string): Promise<string> {
    try {
        const response = await axios.post('https://oauth2.googleapis.com/token', {
            client_id: conf.googleClientId,
            client_secret: conf.googleClientSecret,
            grant_type: 'refresh_token',
            refresh_token: refreshToken
        });

        // Extract the access token and expiration time from the response
        const { access_token: accessToken, expires_in } = response.data;

        // Calculate the expiry time in milliseconds
        const currentTime = Date.now();
        const expiryTime = currentTime + (expires_in * 1000);
        const expiresAt = new Date(expiryTime);

        // Update the expiry time and access token in the database (this part is not implemented in the function)
        try {
            await User.findByIdAndUpdate(userId, {
                $set: {
                    'googleAuthInfo.expiresAt': expiresAt,
                    'googleAuthInfo.accessToken': accessToken
                }
            });
        } catch (error) {
            console.error('Error updating token expiration and access token:', error);
            handleAxiosError(error, 'Failed to update token expiration and access token');
        }

        return accessToken;
    } catch (error) {
        console.error('Error refreshing access token:', error);
        handleAxiosError(error, 'Failed to refresh access token');
    }
}