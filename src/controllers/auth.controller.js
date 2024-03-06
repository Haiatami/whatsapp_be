import asyncHandler from 'express-async-handler';
import createHttpError from 'http-errors';
import validator from 'validator';
import bcrypt from 'bcrypt';
import { UserModel } from '../models/index.js';
import parser from 'ua-parser-js';
import { generateToken, hashToken } from '../utils/index.js';
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
