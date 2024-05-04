// src/types/express/index.d.ts

import { SessionUser, User } from "../custom";

// to make the file a module and avoid the TypeScript error
export {}

declare global {
  namespace Express {
    export interface Request {
      user?: User;
    }
  }
}

declare module 'express-session' {
  interface Session {
      user: SessionUser; // Extend the Express session with your custom user type
  }
}