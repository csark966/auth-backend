const mongoose = require("mongoose");

const userSchema = new mongoose.Schema(
  {
    userId: {
      type: String,
      required: true,
      unique: true,
      default: () => `user_${Date.now()}`,
    },
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    firstName: String,
    lastName: String,
    gender: { type: String, enum: ["male", "female", "other"] },
    phoneNo: String,
    dateOfBirth: Date,
    address: String,
    profileImage: String,
  },
  { timestamps: true }
);

module.exports = mongoose.model("User", userSchema);
