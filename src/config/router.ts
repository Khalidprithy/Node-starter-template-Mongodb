// src/config/router.ts

import express from 'express';
import path from 'path';
import userRoute from '../api/userRoute';
import verifyAuthJWT from '../middlewares/verifyAuthJWT';

const createRoutes = (app: express.Application): void => {
   // 'public' directory access
   app.use(express.static(path.join(__dirname, '../../public')));

   // secure routes starts with '/api'
   app.use('/api/user', userRoute);
   app.use(verifyAuthJWT); // Bellow this middleware routes will require auth access token
   // Other routes here
};

export default createRoutes;
