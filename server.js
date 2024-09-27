// const bcrypt = require("bcrypt");
// const jwt = require("jsonwebtoken");
// const crypto = require("crypto");
// const User = require("../models/user");
// const RefreshToken = require("../models/refreshToken");
// const OTP = require("../models/otp");
// const { sendOTP } = require("../services/emailService");

// // User Registration
// exports.register = async (req, res) => {
//   try {
//     const hashedPassword = await bcrypt.hash(req.body.password, 10);
//     const user = new User({
//       email: req.body.email,
//       password: hashedPassword,
//       role: req.body.role || "user",
//     });
//     const newUser = await user.save();
//     res.status(201).json(newUser);
//   } catch (err) {
//     console.log(err);
//     res.status(400).json({ message: err.message });
//   }
// };

// // Profile Management
// exports.profileManagement = async (req, res) => {
//   try {
//     const user = await User.findOne({ email: req.user.email });
//     if (!user) {
//       return res.status(404).json({ message: "User not found" });
//     }

//     if (!req.body.email) {
//       return res.status(400).json({ message: "Email is required" });
//     }

//     user.firstName = req.body.firstName || user.firstName;
//     user.lastName = req.body.lastName || user.lastName;
//     user.gender = req.body.gender || user.gender;
//     user.email = req.body.email;
//     user.phoneNo = req.body.phoneNo || user.phoneNo;
//     user.dateOfBirth = req.body.dateOfBirth || user.dateOfBirth;
//     user.address = req.body.address || user.address;

//     if (req.file) {
//       user.profileImage = req.file.path;
//     }

//     const updatedUser = await user.save();
//     res.json(updatedUser);
//   } catch (err) {
//     res.status(400).json({ message: err.message });
//   }
// };

// // User Login
// exports.login = async (req, res) => {
//   try {
//     const user = await User.findOne({ email: req.body.email });
//     if (!user) return res.status(400).json({ message: "Cannot find user" });

//     if (await bcrypt.compare(req.body.password, user.password)) {
//       const accessToken = generateAccessToken({
//         email: user.email,
//         role: user.role,
//       });
//       const refreshToken = jwt.sign(
//         { email: user.email, role: user.role },
//         process.env.REFRESH_TOKEN_SECRET
//       );
//       const newRefreshToken = new RefreshToken({ token: refreshToken });
//       await newRefreshToken.save();
//       res.json({ accessToken, refreshToken, email: req.body.email });
//     } else {
//       res.status(401).json({ message: "Incorrect password" });
//     }
//   } catch (error) {
//     res.status(500).json({ message: error.message });
//   }
// };

// // Token Refresh
// exports.refreshToken = async (req, res) => {
//   const refreshToken = req.body.token;
//   if (refreshToken == null) return res.sendStatus(401);
//   const storedToken = await RefreshToken.findOne({ token: refreshToken });
//   if (!storedToken) return res.sendStatus(403);
//   jwt.verify(refreshToken, process.env.REFRESH_TOKEN_SECRET, (err, user) => {
//     if (err) return res.sendStatus(403);
//     const accessToken = generateAccessToken({
//       email: user.email,
//       role: user.role,
//     });
//     const newRefreshToken = jwt.sign(
//       { email: user.email, role: user.role },
//       process.env.REFRESH_TOKEN_SECRET
//     );
//     res.json({ accessToken, refreshToken: newRefreshToken, email: user.email });
//   });
// };

// // Forgot Password
// exports.forgotPassword = async (req, res) => {
//   try {
//     const user = await User.findOne({ email: req.body.email });
//     if (!user) {
//       return res.status(404).json({ message: "User not found" });
//     }

//     const otp = crypto.randomInt(100000, 999999).toString();
//     const newOTP = new OTP({
//       email: user.email,
//       otp: otp,
//     });
//     await newOTP.save();

//     await sendOTP(user.email, otp);

//     res.json({ message: "OTP sent to your email" });
//   } catch (error) {
//     res.status(500).json({ message: error.message });
//   }
// };

// // Reset Password
// exports.resetPassword = async (req, res) => {
//   try {
//     const { email, otp, newPassword } = req.body;

//     const otpDoc = await OTP.findOne({ email, otp });
//     if (!otpDoc) {
//       return res.status(400).json({ message: "Invalid OTP" });
//     }

//     const user = await User.findOne({ email });
//     if (!user) {
//       return res.status(404).json({ message: "User not found" });
//     }

//     const hashedPassword = await bcrypt.hash(newPassword, 10);
//     user.password = hashedPassword;
//     await user.save();

//     await OTP.deleteOne({ _id: otpDoc._id });

//     res.json({ message: "Password reset successful" });
//   } catch (error) {
//     res.status(500).json({ message: error.message });
//   }
// };

// // User Logout
// exports.logout = async (req, res) => {
//   try {
//     await RefreshToken.deleteOne({ token: req.body.token });
//     res.sendStatus(204);
//   } catch (error) {
//     res.status(500).json({ message: error.message });
//   }
// };

// // Protected Routes
// exports.adminRoute = (req, res) => {
//   res.json({ message: "Welcome Admin" });
// };

// exports.userRoute = (req, res) => {
//   res.json({ message: "Welcome User" });
// };

// // Helper function to generate access token
// function generateAccessToken(user) {
//   return jwt.sign(user, process.env.ACCESS_TOKEN_SECRET, { expiresIn: "15m" });
// }
// ---------------------------------------------------------------------------------------------------------

require("dotenv").config();
const express = require("express");
const mongoose = require("mongoose");
const authRoutes = require("./routes/authRoutes");
const cors = require("cors");
const app = express();
app.use(cors());
// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Connect to MongoDB
mongoose
  .connect(process.env.DATABASE_URL, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
  })
  .then(() => console.log("Connected to Database"))
  .catch((error) => console.error("Database connection error:", error));

// Routes
app.use("/auth", authRoutes);

// Start server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
