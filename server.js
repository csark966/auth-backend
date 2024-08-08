require("dotenv").config();
const express = require("express");
const mongoose = require("mongoose");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcrypt");
const User = require("./models/user");
const RefreshToken = require("./models/refreshToken");
const authenticateToken = require("./middlewares/authMiddleware");
const authorizeRole = require("./middlewares/roleMiddleware");
const upload = require("./config/multerConfig");
const crypto = require("crypto");
const { sendOTP } = require("./emailService");
const OTP = require("./models/otp");

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

mongoose.connect(process.env.DATABASE_URL, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
});

const db = mongoose.connection;
db.on("error", (error) => console.error(error));
db.once("open", () => console.log("Connected to Database"));

// User Registration Route
app.post("/register", async (req, res) => {
  try {
    const hashedPassword = await bcrypt.hash(req.body.password, 10);
    const user = new User({
      // userName: req.body.userName,
      email: req.body.email,
      password: hashedPassword,
      role: req.body.role || "user",
    });
    const newUser = await user.save();
    res.status(201).json(newUser);
  } catch (err) {
    console.log(err);
    res.status(400).json({ message: err.message });
  }
});

// Profile management route
app.post(
  "/profilemanagement",
  upload.single("profileImage"),
  authenticateToken,
  async (req, res) => {
    try {
      const user = await User.findOne({ email: req.user.email });
      if (!user) {
        return res.status(404).json({ message: "User not found" });
      }

      // Check if email is provided
      if (!req.body.email) {
        return res.status(400).json({ message: "Email is required" });
      }

      // Update user profile
      user.firstName = req.body.firstName || user.firstName;
      user.lastName = req.body.lastName || user.lastName;
      user.gender = req.body.gender || user.gender;
      user.email = req.body.email; // Email is now required
      user.phoneNo = req.body.phoneNo || user.phoneNo;
      user.dateOfBirth = req.body.dateOfBirth || user.dateOfBirth;
      user.address = req.body.address || user.address;

      if (req.file) {
        user.profileImage = req.file.path;
      }

      const updatedUser = await user.save();
      res.json(updatedUser);
    } catch (err) {
      res.status(400).json({ message: err.message });
    }
  }
);

// User Login Route
app.post("/login", async (req, res) => {
  const user = await User.findOne({ email: req.body.email });

  if (!user) return res.status(400).json({ message: "Cannot find user" });

  if (await bcrypt.compare(req.body.password, user.password)) {
    const accessToken = generateAccessToken({
      email: user.email,
      role: user.role,
    });
    const refreshToken = jwt.sign(
      { email: user.email, role: user.role },
      process.env.REFRESH_TOKEN_SECRET
    );
    const newRefreshToken = new RefreshToken({ token: refreshToken });
    await newRefreshToken.save();
    res.json({ accessToken, refreshToken, email: req.body.email });
  } else {
    res.status(401).json({ message: "Incorrect password" });
  }
});

// Token Refresh Route
app.post("/token", async (req, res) => {
  const refreshToken = req.body.token;
  if (refreshToken == null) return res.sendStatus(401);
  const storedToken = await RefreshToken.findOne({ token: refreshToken });
  if (!storedToken) return res.sendStatus(403);
  jwt.verify(refreshToken, process.env.REFRESH_TOKEN_SECRET, (err, user) => {
    if (err) return res.sendStatus(403);
    const accessToken = generateAccessToken({
      email: user.email,
      role: user.role,
    });
    const newRefreshToken = jwt.sign(
      { email: user.email, role: user.role },
      process.env.REFRESH_TOKEN_SECRET
    );
    res.json({ accessToken, refreshToken: newRefreshToken, email: user.email });
  });
});

// Forgot Password Route
app.post("/forgot-password", async (req, res) => {
  try {
    const user = await User.findOne({ email: req.body.email });
    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    // Generate OTP
    const otp = crypto.randomInt(100000, 999999).toString();

    // Save OTP to database
    const newOTP = new OTP({
      email: user.email,
      otp: otp,
    });
    await newOTP.save();

    // Send OTP via email
    await sendOTP(user.email, otp);

    res.json({ message: "OTP sent to your email" });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

// Verify OTP and Reset Password Route
app.post("/reset-password", async (req, res) => {
  try {
    const { email, otp, newPassword } = req.body;

    // Verify OTP
    const otpDoc = await OTP.findOne({ email, otp });
    if (!otpDoc) {
      return res.status(400).json({ message: "Invalid OTP" });
    }

    // Find user and update password
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    const hashedPassword = await bcrypt.hash(newPassword, 10);
    user.password = hashedPassword;
    await user.save();

    // Delete used OTP
    await OTP.deleteOne({ _id: otpDoc._id });

    res.json({ message: "Password reset successful" });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

// User Logout Route
app.delete("/logout", async (req, res) => {
  await RefreshToken.deleteOne({ token: req.body.token });
  res.sendStatus(204);
});

// Protected Route Example
app.get("/admin", authorizeRole(["admin"]), (req, res) => {
  res.json({ message: "Welcome Admin" });
});

app.get("/user", authorizeRole(["user", "admin"]), (req, res) => {
  res.json({ message: "Welcome User" });
});

function generateAccessToken(user) {
  return jwt.sign(user, process.env.ACCESS_TOKEN_SECRET, { expiresIn: "15m" });
}

app.listen(3000, () => console.log("Authentication Service Started"));
