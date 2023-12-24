// src/controllers/userController.ts
import bcrypt from 'bcrypt';
import { NextFunction, Request, Response } from 'express';
import { validationResult } from 'express-validator';
import jwt from 'jsonwebtoken';
import { generateJsonWebToken } from '../helpers/generateJsonWebToken';
import UserModel from '../models/User';

// ********************** Registration ********************** //
export const Registration = async (
   req: Request,
   res: Response,
   next: NextFunction
): Promise<void | Response<any, Record<string, any>>> => {
   try {
      const errors = validationResult(req);
      if (!errors.isEmpty()) {
         return res
            .status(422)
            .json({ success: false, errors: errors.array() });
      }

      const { name, email, password, role, image, designation } = req.body;

      const userExists = await UserModel.findOne({ email });

      if (userExists) {
         res.status(422).json({
            success: false,
            error: 'User with the same email already exists. Please choose a different email.'
         });
      }

      const hashedPassword = await bcrypt.hash(password, 10);

      const refreshToken = generateJsonWebToken(
         { name: name, email: email },
         process.env.JWT_SECRET_REFRESH as string,
         '7d'
      );

      const userModel = new UserModel({
         name,
         email,
         password: hashedPassword,
         role,
         image,
         designation,
         refreshToken
      });

      const savedUser = await userModel.save();

      const accessToken = generateJsonWebToken(
         { userId: savedUser._id, email: savedUser.email },
         process.env.JWT_SECRET_ACCESS as string,
         '1h'
      );

      // Res with http only cookie token
      res.cookie('jwt', refreshToken, {
         httpOnly: true,
         maxAge: 24 * 60 * 60 * 1000
      });
      res.json({
         success: true,
         accessToken,
         user: {
            name: savedUser.name,
            email: savedUser.email,
            image: savedUser.image,
            role: savedUser.role
         }
      });
   } catch (error) {
      console.error('Error saving user to MongoDB:', error);
      next(error);
   }
};

// ********************** Login ********************** //
export const Login = async (
   req: Request,
   res: Response,
   next: NextFunction
): Promise<void | Response<any, Record<string, any>>> => {
   try {
      const errors = validationResult(req);
      if (!errors.isEmpty()) {
         return res
            .status(422)
            .json({ success: false, errors: errors.array() });
      }

      const { email, password } = req.body;

      // Find the user
      const user = await UserModel.findOne({ email });

      // user is not found or password is invalid
      if (!user || !(await bcrypt.compare(password, user.password))) {
         return res
            .status(401)
            .json({ success: false, error: 'Invalid email or password' });
      }

      // (access token and refresh token)
      const accessToken = generateJsonWebToken(
         { userId: user._id, email: user.email },
         process.env.JWT_SECRET_ACCESS as string,
         '1h'
      );
      const refreshToken = generateJsonWebToken(
         { name: user.name, email: user.email },
         process.env.JWT_SECRET_REFRESH as string,
         '7d'
      );

      // Update the user document with the new refresh token
      await UserModel.updateOne({ email }, { refreshToken });

      // Res with http only cookie token
      res.cookie('jwt', refreshToken, {
         httpOnly: true,
         maxAge: 24 * 60 * 60 * 1000
      });
      res.json({
         success: true,
         accessToken,
         user: {
            name: user.name,
            email: user.email,
            image: user.image
         }
      });
   } catch (error) {
      console.error('Error during login:', error);
      next(error);
   }
};

// ********************** Token Refresh ********************** //
export const RefreshAccessToken = async (
   req: Request,
   res: Response,
   next: NextFunction
): Promise<void | Response<any, Record<string, any>>> => {
   try {
      const cookies = req.cookies;

      if (!cookies?.jwt) {
         return res.status(401).json({
            success: false,
            error: 'Unauthorized: Missing refresh token'
         });
      }

      const refreshToken = cookies.jwt;

      // Find the user
      const foundUser = await UserModel.findOne({ refreshToken });

      // Check if it's a valid user
      if (!foundUser) {
         return res.status(403).json({
            success: false,
            error: 'Forbidden access: User not found'
         });
      }

      // Verify the refresh token
      jwt.verify(
         refreshToken,
         process.env.JWT_SECRET_REFRESH as string,
         (err: any, decoded: any) => {
            if (err || foundUser.email !== decoded.email) {
               return res.status(403).json({
                  success: false,
                  error: 'Forbidden access: Invalid refresh token'
               });
            }

            // Extract userId and email from the decoded refresh token
            const { name, email } = decoded as {
               name: string;
               email: string;
            };

            // Generate a new access token
            const newAccessToken = generateJsonWebToken(
               { name, email },
               process.env.JWT_SECRET_ACCESS as string,
               '1h'
            );

            res.json({
               success: true,
               accessToken: newAccessToken
            });
         }
      );
   } catch (error) {
      console.error('Error refreshing access token:', error);
      next(error);
   }
};

// ********************** Get User Profile ********************** //
export const GetUserProfile = async (
   req: Request,
   res: Response,
   next: NextFunction
): Promise<void | Response<any, Record<string, any>>> => {
   const userId = req.params.id;

   try {
      // Find the user by ID
      const user = await UserModel.findById(userId);

      // User not found
      if (!user) {
         return res
            .status(404)
            .json({ success: false, error: 'User not found' });
      }

      // Return user profile
      res.json({
         success: true,
         user: {
            name: user.name,
            email: user.email,
            image: user.image,
            designation: user.designation
         }
      });
   } catch (error) {
      console.error('Error getting user profile:', error);
      next(error);
   }
};

// ********************** Update Profile ********************** //
export const UpdateUser = async (
   req: Request,
   res: Response,
   next: NextFunction
): Promise<void | Response<any, Record<string, any>>> => {
   // Express-validator
   const errors = validationResult(req);
   if (!errors.isEmpty()) {
      return res.status(422).json({ success: false, errors: errors.array() });
   }

   const userId = req.params.id;
   const { name, image, designation } = req.body;

   try {
      // Find the user
      const user = await UserModel.findById(userId);

      // user is not found
      if (!user) {
         return res
            .status(404)
            .json({ success: false, error: 'User not found' });
      }

      user.name = name || user.name;
      user.image = image || user.image;
      user.designation = designation || user.designation;
      await user.save();

      res.json({
         success: true,
         user: {
            name: user.name,
            email: user.email,
            image: user.image,
            designation: user.designation
         }
      });
   } catch (error) {
      console.error('Error updating user:', error);
      next(error);
   }
};

// ********************** Change Password ********************** //
export const ChangePassword = async (
   req: Request,
   res: Response,
   next: NextFunction
): Promise<void | Response<any, Record<string, any>>> => {
   try {
      const errors = validationResult(req);
      if (!errors.isEmpty()) {
         return res
            .status(422)
            .json({ success: false, errors: errors.array() });
      }

      const userId = req.params.id;
      const { oldPassword, newPassword } = req.body;

      // Find the user
      const user = await UserModel.findById(userId);

      // user is not found
      if (!user) {
         return res
            .status(404)
            .json({ success: false, error: 'User not found' });
      }

      // Compare old password
      const isPasswordValid = await bcrypt.compare(oldPassword, user.password);

      if (!isPasswordValid) {
         return res
            .status(401)
            .json({ success: false, error: 'Invalid old password' });
      }

      // Hash new password
      const hashedNewPassword = await bcrypt.hash(newPassword, 10);

      // Update user's password
      user.password = hashedNewPassword;
      await user.save();

      // (access token)
      const accessToken = generateJsonWebToken(
         { userId: user._id, email: user.email },
         process.env.JWT_SECRET_ACCESS as string,
         '1h'
      );

      res.json({
         success: true,
         accessToken,
         user: {
            name: user.name,
            email: user.email,
            image: user.image
         }
      });
   } catch (error) {
      console.error('Error changing password:', error);
      next(error);
   }
};

// ********************** All Users ********************** //
export const GetAllUsers = async (
   req: Request,
   res: Response,
   next: NextFunction
): Promise<void | Response<any, Record<string, any>>> => {
   try {
      const users = await UserModel.find({}, { password: 0, __v: 0 });

      res.json({ success: true, users });
   } catch (error) {
      console.error('Error getting all users:', error);
      next(error);
   }
};

// ********************** Delete User ********************** //
export const DeleteUser = async (
   req: Request,
   res: Response,
   next: NextFunction
): Promise<void | Response<any, Record<string, any>>> => {
   // Express-validator
   const errors = validationResult(req);
   if (!errors.isEmpty()) {
      return res.status(422).json({ success: false, errors: errors.array() });
   }
   const { email, password } = req.body;

   try {
      // Find the user
      const user = await UserModel.findOne({ email });

      // user is not found
      if (!user) {
         return res
            .status(404)
            .json({ success: false, error: 'User not found' });
      }

      // Compare password
      const isPasswordValid = await bcrypt.compare(password, user.password);

      if (!isPasswordValid) {
         return res
            .status(401)
            .json({ success: false, error: 'Invalid password' });
      }

      // Delete user
      await UserModel.findByIdAndDelete(user._id);

      res.json({ success: true, message: 'User deleted successfully' });
   } catch (error) {
      console.error('Error deleting user:', error);
      next(error);
   }
};
