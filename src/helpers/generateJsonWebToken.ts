import jwt from 'jsonwebtoken';

// Helpers
export const generateJsonWebToken = (
   payload: any,
   secret: string,
   expiresIn: string
) => {
   return jwt.sign(payload, secret, { expiresIn });
};
