import mongoose, { Schema } from "mongoose";


export interface ResetPassword extends Document{
    user_id: string;
    resetToken: string;
    timestamp: Date;
}

const resetPasswordSchema = new Schema(
    {
        user_id: {
            type: Schema.Types.ObjectId,
            ref: "User",
            required: true
        },
        resetToken: {
            type: String,
            required: true
        },
        timestamp: {
            type: Date,
            default: Date.now,
            required: true,
            get: (timestamp: Date) => timestamp.getTime(),
            set: (timestamp: any) => new Date(timestamp)
        }
    }, {
    timestamps: true,
}
)


export default mongoose.model<ResetPassword>("ResetPassword",resetPasswordSchema)