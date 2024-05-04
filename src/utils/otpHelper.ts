

export const hasOneMinutePassed = (oldTimestamp: number): boolean => {
    try {
        const c_datetime = new Date();
        let differenceValue = (oldTimestamp - c_datetime.getTime()) / 1000;
        differenceValue /= 60;
        if (Math.abs(differenceValue) > 1) {
            return true;
        }

        return false;
    } catch (error) {
        console.log("error in hasOneMinutePassed function");
        return false;
    }
}
export const hasOtpExpired = (oldTimestamp: number): boolean => {
    try {
        const c_datetime = new Date();
        let differenceValue = (oldTimestamp - c_datetime.getTime()) / 1000;
        differenceValue /= 60;
        
        // OTP will expire after 10 min
        if (Math.abs(differenceValue) > 10) {
            return true;
        }

        return false;
    } catch (error) {
        console.log("error in hasOtpExpired function");
        return false;
    }
}