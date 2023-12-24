// src/api/userRoute.ts

import express from 'express';
import { body } from 'express-validator';
import {
   ChangePassword,
   DeleteUser,
   GetAllUsers,
   GetUserProfile,
   Login,
   RefreshAccessToken,
   Registration,
   UpdateUser
} from '../controllers/userController';

const router = express.Router();

// Common validation middleware
const emailValidation = body('email')
   .isEmail()
   .withMessage('Invalid email format');
const passwordValidation = body('password')
   .notEmpty()
   .withMessage('Password is required');
const nameValidation = body('name').notEmpty().withMessage('Name is required');
const imageValidation = body('image')
   .optional()
   .isURL()
   .withMessage('Invalid image URL format');
const designationValidation = body('designation')
   .optional()
   .notEmpty()
   .withMessage('Designation is required');
const newPasswordValidation = body('newPassword')
   .isLength({ min: 6 })
   .withMessage('New password must be at least 6 characters long');

// Create User Route Validation
const createUserValidation = [
   nameValidation,
   emailValidation,
   passwordValidation
];

// login Route Validation
const loginValidation = [emailValidation, passwordValidation];

// Update User Route Validation
const updateUserValidation = [
   nameValidation,
   imageValidation,
   designationValidation
];

// Change Password Route Validation
const changePasswordValidation = [passwordValidation, newPasswordValidation];

// Delete User Route Validation
const deleteUserValidation = [emailValidation, passwordValidation];

router.post('/create', createUserValidation, Registration);
router.post('/login', loginValidation, Login);
router.post('/refresh-token', RefreshAccessToken);
router.post('/change-password/:id', changePasswordValidation, ChangePassword);
router.get('/all', GetAllUsers);
router.post('/profile/:id', GetUserProfile);
router.put('/update/:id', updateUserValidation, UpdateUser);
router.delete('/delete', deleteUserValidation, DeleteUser);

export default router;
