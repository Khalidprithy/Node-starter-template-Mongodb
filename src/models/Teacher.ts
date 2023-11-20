// src/models/Teacher.ts

import mongoose, { Document, Schema } from 'mongoose';

export interface ITeacher extends Document {
   name: string;
   subject: string;
   qualification: string;
   experience: string;
   contactInfo: string;
}

const teacherSchema: Schema = new Schema({
   name: {
      type: String,
      required: true
   },
   subject: {
      type: String,
      required: true
   },
   qualification: {
      type: String,
      required: true
   },
   experience: {
      type: String,
      required: true
   },
   contactInfo: {
      type: String,
      required: true
   }
});

const TeacherModel = mongoose.model<ITeacher>('Teacher', teacherSchema);

export default TeacherModel;
