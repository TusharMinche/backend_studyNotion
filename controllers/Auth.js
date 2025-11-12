const User = require("../models/User");
const OTP = require("../models/OTP");
const otpGenerator = require("otp-generator");
const bcrypt = require("bcrypt");
const Profile = require("../models/Profile");
const jwt = require("jsonwebtoken");
require("dotenv").config();
const mailSender = require("../utils/mailSender");
const passwordUpdate = require("../mail/templates/passwordUpdate");

// Send OTP to the user's email
exports.sendOTP = async (req, res) => {
  try {
    const { email } = req.body;

    const checkUserPresent = await User.findOne({ email });

    if (checkUserPresent) {
      return res.status(401).json({
        success: false,
        message: "User already registered",
      });
    }

    var otp = otpGenerator.generate(6, {
      upperCaseAlphabets: false,
      lowerCaseAlphabets: false,
      specialChars: false,
    });

    let result = await OTP.findOne({ otp: otp });

    while (result) {
      otp = otpGenerator(6, {
        upperCaseAlphabets: false,
        lowerCaseAlphabets: false,
        specialChars: false,
      });

      result = await OTP.findOne({ otp: otp });
    }

    const otpPayload = { email, otp };

    const otpBody = await OTP.create(otpPayload);

    res.status(200).json({
      success: true,
      message: "OTP sent successfully",
      otp,
    });
  } catch (error) {
    console.log(error);
    res.status(500).json({
      success: false,
      message: error.message,
    });
  }
};

// Register a new user
exports.signUp = async (req, res) => {
  try {
    const {
      email,
      firstName,
      lastName,
      accountType,
      otp,
      password,
      confirmPassword,
    } = req.body;

    // Check if all fields are provided
    if (
      !email ||
      !firstName ||
      !lastName ||
      !otp ||
      !password ||
      !confirmPassword
    ) {
      return res.status(403).json({
        success: false,
        message: "All fields are required",
      });
    }

    // Check if passwords match
    if (password !== confirmPassword) {
      return res.status(400).json({
        success: false,
        message: "Password and Confirm Password do not match. Please try again",
      });
    }

    // Check if user already exists
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({
        success: false,
        message: "User already registered",
      });
    }

    // Verify the OTP
    const recentOtp = await OTP.find({ email })
      .sort({ createdAt: -1 })
      .limit(1);
    if (recentOtp.length === 0) {
      return res.status(400).json({
        success: false,
        message: "OTP Not Found",
      });
    } else if (otp !== recentOtp[0].otp) {
      return res.status(400).json({
        success: false,
        message: "Invalid OTP",
      });
    }

    // Hash the password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Create a profile for the user
    const profileDetails = await Profile.create({
      gender: null,
      dateOfBirth: null,
      about: null,
      contactNumber: null,
    });

    // Create the user
    const user = await User.create({
      email,
      firstName,
      lastName,
      password: hashedPassword,
      accountType,
      additionalDetails: profileDetails._id,
      image: `https://api.dicebear.com/5.x/initials/svg?seed=${firstName} ${lastName}`,
    });

    return res.status(200).json({
      success: true,
      message: "User is registered successfully",
      user,
    });
  } catch (error) {
    console.log(error);
    return res.status(500).json({
      success: false,
      message: "User cannot be registered. Please try again",
    });
  }
};

// Login a user
exports.login = async (req, res) => {
  try {
    const { email, password } = req.body;

    // Check if all fields are provided
    if (!email || !password) {
      return res.status(403).json({
        success: false,
        message: "All fields are required",
      });
    }

    // Find the user in the database
    const user = await User.findOne({ email }).populate("additionalDetails");

    if (!user) {
      return res.status(401).json({
        success: false,
        message: "User is not registered. Please sign up first",
      });
    }

    // Check if the password is correct
    if (await bcrypt.compare(password, user.password)) {
      const payload = {
        email: user.email,
        id: user._id,
        accountType: user.accountType,
      };

      // Generate a JWT token
      const token = jwt.sign(payload, process.env.JWT_SECRET, {
        expiresIn: "2h",
      });

      user.token = token;
      user.password = undefined;

      const options = {
        expires: new Date(Date.now() + 3 * 24 * 60 * 60 * 1000),
        httpOnly: true,
      };

      res.cookie("token", token, options).status(200).json({
        success: true,
        token,
        user,
        message: "Logged in successfully",
      });
    } else {
      return res.status(401).json({
        success: false,
        message: "Password is incorrect",
      });
    }
  } catch (error) {
    console.log(error);
    res.status(500).json({
      success: false,
      message: "Login failed, please try again",
    });
  }
};

// Change the user's password
exports.changePassword = async (req, res) => {
  const { oldPassword, newPassword, confirmPassword } = req.body;

  // Check if all fields are provided
  if (!oldPassword || !newPassword || !confirmPassword) {
    return res.status(403).json({
      success: false,
      message: "Please fill all the fields",
    });
  }

  // Check if the new passwords match
  if (newPassword !== confirmPassword) {
    return res.status(400).json({
      success: false,
      message: "Passwords do not match",
    });
  }

  // Check if the token is provided
  const token = req.cookies.token;
  if (!token) {
    return res.status(400).json({
      success: false,
      message: "Token not found",
    });
  }

  const decoded = jwt.verify(token, process.env.JWT_SECRET);
  const email = decoded.email;

  const user = await User.findOne({ email });

  // Check if the old password is correct
  if (await bcrypt.compare(oldPassword, user.password)) {
    const hashedPassword = await bcrypt.hash(newPassword, 10);

    // Update the user's password in the database
    await User.findOneAndUpdate({ email }, { password: hashedPassword });

    try {
      const mailResponse = await mailSender(
        email,
        "Activity - StudyNotion",
        passwordUpdate({ email, name: user.firstName })
      );
      console.log("Password changed email sent successfully", mailResponse);
    } catch (error) {
      console.log("Error occurred while sending password changed email", error);
      throw error;
    }

    return res.status(200).json({
      success: true,
      message: "Password changed successfully",
    });
  } else {
    return res.status(401).json({
      success: false,
      message: "Old password is incorrect",
    });
  }
};


