import { Schema, model } from "mongoose";

const ROLES = {
  admin: "admin",
  guest: "guest",
  joint: "joint",
};

const userSchema = new Schema(
  {
    firstName: {
      type: String,
      required: true,
    },
    lastName: {
      type: String,
      required: true,
    },
    email: {
      type: String,
      required: true,
    },
    password: {
      type: String,
      required: true,
    },
    role: {
      type: String,
      default: ROLES.guest,
      required: true,
    },
  },
  {
    timestamps: {
      createdAt: true,
      updatedAt: true,
    },
  }
);

const userModel = model("User", userSchema);

export default userModel;
