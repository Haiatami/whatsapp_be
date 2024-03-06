import asyncHandler from 'express-async-handler';
import createHttpError from 'http-errors';
import validator from 'validator';
import bcrypt from 'bcrypt';
import { UserModel, TokenModel } from '../models/index.js';
import parser from 'ua-parser-js';
import { generateToken, hashToken } from '../utils/index.js';
import { sendEmail } from '../utils/sendEmail.js';
import jwt from 'jsonwebtoken';
import crypto from 'crypto';
import Cryptr from 'cryptr';

//env variables
const { DEFAULT_PICTURE } = process.env;

// Register User
export const registerUser = asyncHandler(async (req, res, next) => {
	try {
		const { name, email, password, picture } = req.body;

		//check if fields are empty
		if (!name || !email || !password) {
			throw createHttpError.BadRequest('Please fill all fields.');
		}

		//check name length
		if (
			!validator.isLength(name, {
				min: 2,
				max: 25,
			})
		) {
			throw createHttpError.BadRequest('Plase make sure your name is between 2 and 16 characters.');
		}

		if (password.length < 6) {
			throw createHttpError.BadRequest('Password must be up to 6 characters.');
		}

		//check if email address is valid
		if (!validator.isEmail(email)) {
			throw createHttpError.BadRequest('Please make sure to provide a valid email address.');
		}

		//check if user already exist
		const checkDb = await UserModel.findOne({ email });
		if (checkDb) {
			throw createHttpError.Conflict('Please try again with a different email address, this email already exist.');
		}

		//check password length
		if (
			!validator.isLength(password, {
				min: 6,
				max: 128,
			})
		) {
			throw createHttpError.BadRequest('Please make sure your password is between 6 and 128 characters.');
		}

		// Get UserAgent
		const ua = parser(req.headers['user-agent']);
		const userAgent = [ua.ua];

		//   Create new user
		const user = await UserModel.create({
			name,
			email,
			password,
			picture: picture || DEFAULT_PICTURE,
			userAgent,
		});

		// Generate Token
		const token = generateToken(user._id);

		// Send HTTP-only cookie
		res.cookie('token', token, {
			path: '/',
			httpOnly: true,
			expires: new Date(Date.now() + 1000 * 86400), // 1 day
			sameSite: 'none',
			secure: true,
		});

		if (user) {
			const { _id, name, email, phone, status, picture, role, isVerified } = user;

			res.status(201).json({
				_id,
				name,
				email,
				phone,
				status,
				picture,
				role,
				isVerified,
				token,
			});
		} else {
			throw createHttpError.BadRequest('Invalid user data.');
		}
	} catch (error) {
		next(error);
	}
});

// Login User
export const loginUser = asyncHandler(async (req, res, next) => {
	try {
		const { email, password } = req.body;

		//check if fields are empty
		if (!email || !password) {
			throw createHttpError.BadRequest('Please fill all fields.');
		}

		//check if email address is valid
		if (!validator.isEmail(email)) {
			throw createHttpError.BadRequest('Please make sure to provide a valid email address.');
		}

		if (password.length < 6) {
			throw createHttpError.BadRequest('Password must be up to 6 characters.');
		}

		//check password length
		if (
			!validator.isLength(password, {
				min: 6,
				max: 128,
			})
		) {
			throw createHttpError.BadRequest('Please make sure your password is between 6 and 128 characters.');
		}

		const user = await UserModel.findOne({ email: email.toLowerCase() }).lean();

		if (!user) {
			throw createHttpError.NotFound('User not found, please signup.');
		}

		const passwordIsCorrect = await bcrypt.compare(password, user.password);

		if (!passwordIsCorrect) {
			throw createHttpError.NotFound('Invalid email or password.');
		}

		// Trgger 2FA for unknow UserAgent
		const ua = parser(req.headers['user-agent']);
		const thisUserAgent = ua.ua;
		console.log(thisUserAgent);
		const allowedAgent = user.userAgent.includes(thisUserAgent);

		if (!allowedAgent) {
			// Genrate 6 digit code
			const loginCode = Math.floor(100000 + Math.random() * 900000);
			console.log(loginCode);

			// Encrypt login code before saving to DB
			const encryptedLoginCode = cryptr.encrypt(loginCode.toString());

			// Delete Token if it exists in DB
			let userToken = await TokenModel.findOne({ userId: user._id });

			if (userToken) {
				await userToken.deleteOne();
			}

			// Save Tokrn to DB
			await new TokenModel({
				userId: user._id,
				lToken: encryptedLoginCode,
				createdAt: Date.now(),
				expiresAt: Date.now() + 60 * (60 * 1000), // 60mins
			}).save();

			throw createHttpError.BadRequest('New browser or device detected.');
		}

		// Generate Token
		const token = generateToken(user._id);

		if (user && passwordIsCorrect) {
			// Send HTTP-only cookie
			res.cookie('token', token, {
				path: '/',
				httpOnly: true,
				expires: new Date(Date.now() + 1000 * 86400), // 1 day
				sameSite: 'none',
				secure: true,
			});

			const { _id, name, email, phone, status, picture, role, isVerified } = user;

			res.status(200).json({
				_id,
				name,
				email,
				phone,
				status,
				picture,
				role,
				isVerified,
				token,
			});
		} else {
			throw createHttpError.InternalServerError('Something went wrong, please try again.');
		}
	} catch (error) {
		next(error);
	}
});

// Send Login Code
export const sendLoginCode = asyncHandler(async (req, res, next) => {
	try {
		const { email } = req.params;
		const user = await UserModel.findOne({ email });

		if (!user) {
			throw createHttpError.NotFound('User not found.');
		}

		// Find Login Code in DB
		let userToken = await TokenModel.findOne({
			userId: user._id,
			expiresAt: { $gt: Date.now() },
		});

		if (!userToken) {
			throw createHttpError.NotFound('Invalid or Expired token, please login again.');
		}

		const loginCode = userToken.lToken;
		const decryptedLoginCode = cryptr.decrypt(loginCode);

		// Send Login Code
		const subject = 'Login Access Code - WhatsApp';
		const send_to = email;
		const send_from = process.env.EMAIL_USER;
		const reply_to = 'noreply@hoanghai.com';
		const template = 'loginCode';
		const name = user.name;
		const link = decryptedLoginCode;

		try {
			await sendEmail(subject, send_to, send_from, reply_to, template, name, link);
			res.status(200).json({ message: `Access code sent to ${email}` });
		} catch (error) {
			throw createHttpError.InternalServerError('Email not sent, please try again.');
		}
	} catch (error) {
		next(error);
	}
});

// Send Verification Email
export const sendVerificationEmail = asyncHandler(async (req, res, next) => {
	try {
		const user = await UserModel.findById(req.user._id);

		if (!user) {
			throw createHttpError.NotFound('User not found.');
		}

		if (user.isVerified) {
			throw createHttpError.BadRequest('User already verified.');
		}

		// Delete Token if it exists in DB
		let token = await TokenModel.findOne({ userId: user._id });
		if (token) {
			await token.deleteOne();
		}

		//   Create Verification Token and Save
		const verificationToken = crypto.randomBytes(32).toString('hex') + user._id;

		console.log(verificationToken);

		// Hash token and save
		const hashedToken = hashToken(verificationToken);

		await new TokenModel({
			userId: user._id,
			vToken: hashedToken,
			createdAt: Date.now(),
			expiresAt: Date.now() + 60 * (60 * 1000), // 60mins
		}).save();

		// Construct Verification URL
		const verificationUrl = `${
			process.env.FRONTEND_URL_LOCAL || process.env.FRONTEND_URL_HOST
		}/verify/${verificationToken}`;

		// Send Email
		const subject = 'Verify Your Account - WhatsApp';
		const send_to = user.email;
		const send_from = process.env.EMAIL_USER;
		const reply_to = 'noreply@hoanghai.com';
		const template = 'verifyEmail';
		const name = user.name;
		const link = verificationUrl;

		try {
			await sendEmail(subject, send_to, send_from, reply_to, template, name, link);
			res.status(200).json({ message: 'Verification Email Sent' });
		} catch (error) {
			throw createHttpError.InternalServerError('Email not sent, please try again.');
		}
	} catch (error) {
		next(error);
	}
});

// Verify User
export const verifyUser = asyncHandler(async (req, res, next) => {
	try {
		const { verificationToken } = req.params;

		const hashedToken = hashToken(verificationToken);

		const userToken = await TokenModel.findOne({
			vToken: hashedToken,
			expiresAt: { $gt: Date.now() },
		});

		if (!userToken) {
			throw createHttpError.NotFound('Invalid or Expired Token.');
		}

		// Find User
		const user = await UserModel.findOne({ _id: userToken.userId });

		if (user.isVerified) {
			throw createHttpError.BadRequest('User is already verified.');
		}

		// Now verify user
		user.isVerified = true;

		await user.save();

		res.status(200).json({ message: 'Account Verification Successful' });
	} catch (error) {
		next(error);
	}
});

// Logout User
export const logoutUser = asyncHandler(async (req, res, next) => {
	try {
		res.cookie('token', '', {
			path: '/',
			httpOnly: true,
			expires: new Date(0), // 1 day
			sameSite: 'none',
			secure: true,
		});
		return res.status(200).json({ message: 'Logout successful' });
	} catch (error) {
		next(error);
	}
});

// Get User
export const getUser = asyncHandler(async (req, res, next) => {
	try {
		const user = await UserModel.findById(req.user._id);

		if (user) {
			const { _id, name, email, phone, status, picture, role, isVerified } = user;

			res.status(200).json({
				_id,
				name,
				email,
				phone,
				status,
				picture,
				role,
				isVerified,
			});
		} else {
			throw createHttpError.NotFound('User not found.');
		}
	} catch (error) {
		next(error);
	}
});

// Update User
export const updateUser = asyncHandler(async (req, res, next) => {
	try {
		const user = await UserModel.findById(req.user._id);

		if (user) {
			const { name, email, phone, status, picture, role, isVerified } = user;

			user.email = email;
			user.name = req.body.name || name;
			user.phone = req.body.phone || phone;
			user.status = req.body.status || status;
			user.picture = req.body.picture || picture;

			const updatedUser = await user.save();

			res.status(200).json({
				_id: updatedUser._id,
				name: updatedUser.name,
				email: updatedUser.email,
				phone: updatedUser.phone,
				status: updatedUser.status,
				picture: updatedUser.picture,
				role: updatedUser.role,
				isVerified: updatedUser.isVerified,
			});
		} else {
			throw createHttpError.NotFound('User not found.');
		}
	} catch (error) {
		next(error);
	}
});

// Delete User
export const deleteUser = asyncHandler(async (req, res, next) => {
	try {
		const user = UserModel.findById(req.params.id);

		if (!user) {
			throw createHttpError.NotFound('User not found.');
		}

		await user.deleteOne();

		res.status(200).json({
			message: 'User deleted successfully',
		});
	} catch (error) {
		next(error);
	}
});

// Get Users
export const getUsers = asyncHandler(async (req, res, next) => {
	try {
		const users = await UserModel.find().sort('-createdAt').select('-password');
		if (!users) {
			throw createHttpError.InternalServerError('Something went wrong.');
		}
		res.status(200).json(users);
	} catch (error) {
		next(error);
	}
});

// Login Status
export const loginStatus = asyncHandler(async (req, res, next) => {
	try {
		const token = req.cookies.token;
		if (!token) {
			return res.json(false);
		}

		// Verify token
		const verified = jwt.verify(token, process.env.JWT_SECRET);

		if (verified) {
			return res.json(true);
		}
		return res.json(false);
	} catch (error) {
		next(error);
	}
});

// Upgrade User
export const upgradeUser = asyncHandler(async (req, res, next) => {
	try {
		const { role, id } = req.body;

		const user = await UserModel.findById(id);

		if (!user) {
			throw createHttpError.NotFound('User not found.');
		}

		user.role = role;

		await user.save();

		res.status(200).json({
			message: `User role updated to ${role}`,
		});
	} catch (error) {
		next(error);
	}
});

// Send Automated Email
export const sendAutomatedEmail = asyncHandler(async (req, res, next) => {
	try {
		const { subject, send_to, reply_to, template, url } = req.body;

		if (!subject || !send_to || !reply_to || !template) {
			throw createHttpError.InternalServerError('Missing email parameter.');
		}

		// Get user
		const user = await UserModel.findOne({ email: send_to });

		if (!user) {
			throw createHttpError.NotFound('User not found.');
		}

		const send_from = process.env.EMAIL_USER;
		const name = user.name;
		const link = `${process.env.FRONTEND_URL_LOCAL || process.env.FRONTEND_URL_HOST}${url}`;

		try {
			await sendEmail(subject, send_to, send_from, reply_to, template, name, link);
			res.status(200).json({ message: 'Email Sent' });
		} catch (error) {
			throw createHttpError.InternalServerError('Email not sent, please try again.');
		}
	} catch (error) {
		next(error);
	}
});

// Forgot Password
export const forgotPassword = asyncHandler(async (req, res, next) => {
	try {
		const { email } = req.body;

		const user = await UserModel.findOne({ email });

		if (!user) {
			throw createHttpError.NotFound('No user with this email.');
		}

		// Delete Token if it exists in DB
		let token = await TokenModel.findOne({ userId: user._id });
		if (token) {
			await token.deleteOne();
		}

		//   Create Verification Token and Save
		const resetToken = crypto.randomBytes(32).toString('hex') + user._id;

		console.log(resetToken);

		// Hash token and save
		const hashedToken = hashToken(resetToken);

		await new TokenModel({
			userId: user._id,
			rToken: hashedToken,
			createdAt: Date.now(),
			expiresAt: Date.now() + 60 * (60 * 1000), // 60mins
		}).save();

		// Construct Reset URL
		const resetUrl = `${process.env.FRONTEND_URL_LOCAL || process.env.FRONTEND_URL_HOST}/resetPassword/${resetToken}`;

		// Send Email
		const subject = 'Password Reset Request - WhatsApp';
		const send_to = user.email;
		const send_from = process.env.EMAIL_USER;
		const reply_to = 'noreply@hoanghai.com';
		const template = 'forgotPassword';
		const name = user.name;
		const link = resetUrl;

		try {
			await sendEmail(subject, send_to, send_from, reply_to, template, name, link);
			res.status(200).json({ message: 'Password Reset Email Sent' });
		} catch (error) {
			throw createHttpError.InternalServerError('Email not sent, please try again.');
		}
	} catch (error) {
		next(error);
	}
});

// Reset Password
export const resetPassword = asyncHandler(async (req, res, next) => {
	try {
		const { resetToken } = req.params;
		const { password } = req.body;
		console.log(resetToken);
		console.log(password);

		const hashedToken = hashToken(resetToken);

		const userToken = await TokenModel.findOne({
			rToken: hashedToken,
			expiresAt: { $gt: Date.now() },
		});

		if (!userToken) {
			throw createHttpError.NotFound('Invalid or Expired Token.');
		}

		// Find User
		const user = await UserModel.findOne({ _id: userToken.userId });

		// Now Reset password
		user.password = password;

		await user.save();

		res.status(200).json({ message: 'Password Reset Successful, please login' });
	} catch (error) {
		next(error);
	}
});

// Change Password
export const changePassword = asyncHandler(async (req, res, next) => {
	try {
		const { oldPassword, password } = req.body;
		const user = await UserModel.findById(req.user._id);

		if (!user) {
			throw createHttpError.NotFound('User not found.');
		}

		if (!oldPassword || !password) {
			throw createHttpError.BadRequest('Please enter old and new password.');
		}

		// Check if old password is correct
		const passwordIsCorrect = await bcrypt.compare(oldPassword, user.password);

		// Save new password
		if (user && passwordIsCorrect) {
			user.password = password;

			await user.save();

			res.status(200).json({ message: 'Password change successful, please re-login' });
		} else {
			throw createHttpError.BadRequest('Old password is incorrect.');
		}
	} catch (error) {
		next(error);
	}
});
