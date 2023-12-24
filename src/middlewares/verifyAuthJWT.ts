import { NextFunction, Request, Response } from 'express';
import jwt from 'jsonwebtoken';

// Augmenting the Request type to include a 'user' property
interface AuthenticatedRequest extends Request {
   user?: string; // Adjust the type based on your actual user data
}

const verifyAuthJWT = (
   req: AuthenticatedRequest,
   res: Response,
   next: NextFunction
) => {
   const authHeader = req.headers['authorization'];

   if (!authHeader) return res.sendStatus(401);

   console.log(authHeader);

   const token = authHeader.split(' ')[1];

   jwt.verify(
      token,
      process.env.JWT_SECRET_ACCESS as string, // Assuming JWT_SECRET_ACCESS is a string
      (err, decoded) => {
         if (err) return res.sendStatus(403);

         // Assuming 'name' is a property in your JWT payload
         req.user = (decoded as { name: string }).name;

         next();
      }
   );
};

export default verifyAuthJWT;
