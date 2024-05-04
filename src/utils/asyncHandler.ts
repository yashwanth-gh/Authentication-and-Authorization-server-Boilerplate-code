/*
! this is promise based async handler for try catch base async handler: go here -> './tryCatchAsyncHandler.txt' 
*/

import { NextFunction, Request, Response } from "express";

/*
 * Wraps a request handler function with error handling and async support.
 * @param {function} requestHandler - The request handler function to be wrapped.
 * @returns {function} - The wrapped request handler function.
 */

type requestHandlerType = (req: Request, res: Response, next: NextFunction) => Promise<any>

const asyncHandler = (requestHandler:requestHandlerType) => {
    /*
     * The wrapped request handler function.
     * @param {object} req - The request object.
     * @param {object} res - The response object.
     * @param {function} next - The next middleware function.
     */
    return (req:Request, res:Response, next:NextFunction) => {
        Promise.resolve(requestHandler(req, res, next))
            .catch(err => next(err));
    };
};


export {asyncHandler}

/* 
This code defines a function called `asyncHandler` that takes a `requestHandler` function as an argument. The `asyncHandler` function returns a new function that wraps the `requestHandler` function.
The wrapped function takes three parameters: `req` (the request object), `res` (the response object), and `next` (the next middleware function). Inside the wrapped function, the `requestHandler` function is called with these parameters.
The `requestHandler` function is wrapped inside a `Promise.resolve()` call, which ensures that the `requestHandler` function always returns a promise. If the `requestHandler` function resolves successfully, the promise is resolved and the result is passed to the next middleware function. If the `requestHandler` function throws an error or rejects the promise, the error is caught and passed to the next middleware function.
In summary, this code is a utility function that wraps an asynchronous request handler function and ensures that any errors thrown or rejected promises are properly handled and passed to the next middleware function. */
