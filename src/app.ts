// src/app.ts
import dotenv from 'dotenv';
import express from 'express';
import configureApp from './config/config';
import connectToDatabase from './config/db';
import errorHandler from './config/errorHandler';
import createRoutes from './config/router';

dotenv.config();
const app = express();
const PORT = process.env.PORT || 5000;

// App Configuration and API_KEY middleware
configureApp(app);

// MongoDB connection
connectToDatabase();

// Main Route
createRoutes(app);

// App errorHandler
app.use(errorHandler);

app.listen(PORT, () => {
   console.log(`Backend server running on port ${PORT}`);
});
