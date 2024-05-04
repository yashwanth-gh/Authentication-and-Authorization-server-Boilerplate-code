import { Request, Response, Router } from "express";
import { verifyJWT } from "../middlewares/verifyJWT.middleware.js";
import { verifyAdmin } from "../middlewares/verifyAdmin.middleware.js";
import adminController from "../controllers/admin.controller.js";
import { isAccountActive } from "../middlewares/isAccountActive.middleware.js";

const adminRouter = Router();

const adminMiddlewares = [verifyJWT, verifyAdmin, isAccountActive];

//~ -------- ALL REQUEST HERE SHOULD BE USE 'verifyJWT' AND 'verifyAdmin' MIDDLEWARE --------

//~ see and approve new admin requests
adminRouter.route("/getadmin-details").get(adminMiddlewares, adminController.getCurrentAdmin)
adminRouter.route("/view-pending-admin-requests").get(adminMiddlewares, adminController.viewAllPendingAdminRequests)
adminRouter.route("/approve-admin-request").patch(adminMiddlewares, adminController.approvePendingAdminRequest)
//~ view all users irrespective of their account status
adminRouter.route("/view-users").get(adminMiddlewares, adminController.viewAllUsers)
//~ view all users according to their account status
adminRouter.route("/view-users-by-status").get(adminMiddlewares, adminController.viewAllUsersByAccountStatus)
//~ change account status of a user
adminRouter.route("/change-user-account-status").patch(adminMiddlewares, adminController.changeUserAccountStatus)
export default adminRouter;