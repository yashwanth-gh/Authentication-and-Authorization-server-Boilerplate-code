class ApiError extends Error{

    /*
     * Represents an error object.
     * @class
     * @param {number} statusCode - The status code of the error.
     * @param {string} [message="Something went wrong"] - The error message.
     * @param {Array} [errors=[]] - An array of error objects.
     * @param {string} [stack=""] - The stack trace of the error.
     */

    statusCode: number;
    data: null;
    success: boolean;
    errors: Array<any>;

    constructor(
        statusCode:number,
        message = "Something went wrong",
        errors : Array<any> = [],
        stack=""
    ){
        super(message)
        this.statusCode = statusCode;
        this.data = null;
        this.message = message;
        this.success = false;
        this.errors = errors;

        if(stack){
            this.stack = stack;
        }else{
            Error.captureStackTrace(this,this.constructor)
        }
    }
}

export {ApiError}

//^ Detailed explaination of the code  : 
/*
This code defines a class named `ApiError` that extends the built-in `Error` class in JavaScript. It is designed to represent an error object that can be used in an API context. Here's a brief explanation:

* **Class Definition:**
  - `class ApiError extends Error`: This declares a class named `ApiError` that extends the `Error` class. This means `ApiError` inherits properties and methods from the `Error` class.

* **Constructor:**
  - The class has a constructor method that is called when an instance of `ApiError` is created.
  - The constructor takes four parameters:
    - `statusCode` (number): The HTTP status code of the error.
    - `message` (string): The error message. Defaults to "Something went wrong" if not provided.
    - `errors` (Array): An array of error objects.
    - `stack` (string): The stack trace of the error.

* **Super Constructor:**
  - `super(message)`: Calls the constructor of the parent class (`Error`). It initializes the error message.

* **Properties:**
  - `this.statusCode = statusCode;`: Sets the HTTP status code.
  - `this.data = null;`
  - `this.message = message;`: Sets the error message.
  - `this.success = false;`: Sets the `success` property to `false`.
  - `this.errors = errors;`: Sets the errors property with the provided array of error objects.

* **Stack Trace:**
  - Checks if a stack trace is provided. If yes, sets the stack trace. If not, it captures the stack trace using `Error.captureStackTrace(this, this.constructor)`.

* **Export:**
  - The class is exported using `export { ApiError }`, making it available for import in other files.

This `ApiError` class can be used to create instances of errors in an API context with specific status codes, messages, and error details. It allows for consistent error handling in an API application.
 */
