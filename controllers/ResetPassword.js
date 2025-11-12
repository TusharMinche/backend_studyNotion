const User = require("../models/User");
const mailSender = require("../utils/mailSender");
const bcrypt = require("bcrypt");
const crypto = require("crypto");
const passwordUpdate = require("../mail/templates/passwordUpdate");

// Generate and send a reset password token
exports.resetPasswordToken = async (req, res) => {
    try {
        const email = req.body.email;

        // Find user by email
        const user = await User.findOne({ email });

        if (!user) {
            return res.json({
                success: false,
                message: "Your email is not registered with us",
            });
        }

        // Generate a unique token
        const token = crypto.randomUUID();

        // Update user with reset token and expiration time
        const updatedDetails = await User.findOneAndUpdate({ email: email }, {
            token: token,
            resetPasswordExpires: Date.now() + 5 * 60 * 1000,
        }, { new: true });

        const url = `http://localhost:3000/update-password/${token}`;

        // Send reset password email
        await mailSender(email, "Password reset link", `Password reset link: ${url}`);

        return res.json({
            success: true,
            message: "Email sent successfully. Please check email and change password",
        });
    } catch (error) {
        console.log(error);
        return res.status(500).json({
            success: false,
            message: "Something went wrong while resetting password",
        });
    }
}
// Reset the password using the token
exports.resetPassword = async (req, res) => {
    try {
        const { password, confirmPassword, token } = req.body;

        // Check if passwords match
        if (password !== confirmPassword) {
            return res.json({
                success: false,
                message: "Passwords do not match",
            });
        }

        // Find user by token
        const userDetails = await User.findOne({ token: token });

        if (!userDetails) {
            return res.json({
                success: false,
                message: "Token is invalid",
            });
        }

        // Check if the token is expired
        if (userDetails.resetPasswordExpires < Date.now()) {
            return res.json({
                success: false,
                message: "Token is expired, please regenerate your token",
            });
        }

        // Hash the new password
        const hashedPassword = await bcrypt.hash(password, 10);

        // Update user's password
        await User.findOneAndUpdate({ token: token }, { password: hashedPassword, token: null, resetPasswordExpires: null }, { new: true });

        return res.status(200).json({
            success: true,
            message: "Password reset successful",
        });
    } catch (error) {
        console.log(error);
        return res.status(500).json({
            success: false,
            message: "Something went wrong while resetting the password",
        });
    }
}


