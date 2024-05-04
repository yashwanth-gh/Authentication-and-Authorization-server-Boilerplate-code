import { ApiError } from "./ApiError.js";

/**
 * Handle errors from Axios requests and throw appropriate ApiError.
 * @param error The error object from Axios.
 */
export function handleAxiosError(error: any,customMessage:string=''): never {
    console.error("Axios request error:", error);

    if (error.response) {
        const status = error.response.status;
        if (status >= 400 && status < 500) {
            // Client errors (4xx)
            throw new ApiError(status, error.response.data.message || `Client error : ${customMessage}`);
        } else if (status >= 500) {
            // Server errors (5xx)
            throw new ApiError(status, `Server error : ${customMessage}`);
        } else {
            // Other status codes
            throw new ApiError(status, `Unknown error : ${customMessage}`);
        }
    } else if (error.request) {
        // No response received
        throw new ApiError(500, `Failed to receive response from server : ${customMessage}`);
    }

    // Other errors
    throw new ApiError(500, `Unknown error occurred during API request : ${customMessage}`);
}