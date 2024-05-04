import { Router } from "express";
import { changePasswordValidation } from "../middlewares/authDataValidation.middleware.js";
import {verifyJWT} from '../middlewares/verifyJWT.middleware.js';
import userControllers from "../controllers/user.controller.js";
import { isAccountActive } from "../middlewares/isAccountActive.middleware.js";


const userRouter = Router();

//~ --------- PRIVATE ROUTES ---------
userRouter.route("/change-password").post([verifyJWT,isAccountActive,changePasswordValidation],userControllers.changeCurrentPassword)
userRouter.route("/change-fullname").patch(verifyJWT,isAccountActive,userControllers.changeUserFullname)
userRouter.route("/delete-account").delete(verifyJWT,isAccountActive,userControllers.deleteUserAccount)

export default userRouter;