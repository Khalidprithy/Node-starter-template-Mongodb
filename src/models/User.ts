// src/models/User.ts
import mongoose, { Document, Schema } from 'mongoose';

interface User extends Document {
   name: string;
   email: string;
   password: string;
   role: string;
   image: string;
   designation: string;
   refreshToken: string;
}

const userSchema: Schema<User> = new mongoose.Schema({
   name: { type: String, required: true },
   email: { type: String, required: true, unique: true },
   password: { type: String, required: true },
   role: { type: String, required: true },
   image: { type: String, required: true },
   designation: { type: String, required: true },
   refreshToken: { type: String, required: true, unique: true }
});

const UserModel = mongoose.model<User>('User', userSchema);

export default UserModel;
