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
			res.status(400);
			throw new Error('Password must be up to 6 characters.');
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
			res.status(400);
			throw new Error('Invalid user data');
		}
	} catch (error) {
		next(error);
	}
});

export const loginUser = asyncHandler(async (req, res, next) => {
	try {
	} catch (error) {
		next(error);
	}
});

export const logoutUser = asyncHandler(async (req, res, next) => {
	try {
	} catch (error) {
		next(error);
	}
});
