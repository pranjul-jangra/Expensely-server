import mongoose from "mongoose";


export const connectDb = async () => {
    try{
        await mongoose.connect(process.env.MONGOURL);
        console.log("Connected to MongoDB");

    }catch(error){
        console.log("Error connecting db");
    }
}