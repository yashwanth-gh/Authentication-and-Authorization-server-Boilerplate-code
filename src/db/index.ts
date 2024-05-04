import mongoose from "mongoose";
import { DB_NAME, conf } from "../constants.js";


const DB_CONNECT = async():Promise<void>=>{
    try {
        const connectionInstance = await mongoose.connect(`${conf.mongoURI}/|${DB_NAME}`)
        console.log("DB_CONNECT :: MongoDB connected successfully!")
        console.log(`\n DB HOST : ${connectionInstance.connection.host}`)
    } catch (error) {
        console.error("ERROR :: DB_CONNECT :: MongoDB connection failed!")
        process.exit(1);
    }
}

export default DB_CONNECT;