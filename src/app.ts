import express, { Express, Response, Request } from "express";
import cors from 'cors';
import cookieParser from "cookie-parser";
import path from 'path';
import session from 'express-session';
import MongoStore from 'connect-mongo';
import morgan from 'morgan';

const app: Express = express();

app.use(cors({
    origin: process.env.CORS_ORIGIN,
    credentials: true
}))

app.use(express.json());

app.use(express.urlencoded({ extended: true }));

app.use(express.static(path.resolve("public")));

app.use(morgan("common"));

app.use(cookieParser());

app.use(session({
    name: conf.sessionName,
    secret: conf.sessionSecret,
    resave: false,
    saveUninitialized: false,
    cookie: {
        httpOnly: true,
        secure: conf.nodeEnv === 'production',
        maxAge: parseInt(conf.sessionExpiry)
    },
    store: MongoStore.create({
        mongoUrl: conf.mongoURI,
        collectionName: 'session',
        ttl: parseInt(conf.sessionExpiry) / 1000,
    })
}));

//* --Api routes

import authRouter from './routes/auth.route.js';
app.use("/api/v1/auth", authRouter)

import userRouter from './routes/user.route.js';
app.use("/api/v1/users", userRouter)

import adminRouter from './routes/admin.route.js';
import { CustomSessionOptions } from "./types/custom/index.js";
import { conf } from "./constants.js";
import { Console } from "console";
app.use("/api/v1/admin", adminRouter)


export { app };