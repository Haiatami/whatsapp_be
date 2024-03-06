import asyncHandler from 'express-async-handler';
import { UserModel } from '../models/index.js';
import jwt from 'jsonwebtoken';
import createHttpError from 'http-errors';

export const protect = asyncHandler(async (req, res, next) => {
	try {
		try {
			const token = req.cookies.token;

			if (!token) {
				throw createHttpError.Unauthorized('Not authorized, please login.');
			}

			// Verify token
			const verified = jwt.verify(token, process.env.JWT_SECRET);

			// Get user id from token
			const user = await UserModel.findById(verified.id).select('-password');

			if (!user) {
				throw createHttpError.NotFound('User not found.');
			}

			if (user.role === 'suspended') {
				throw createHttpError.BadRequest('User suspended, please contact support.');
			}

			req.user = user;

			next();
		} catch (error) {
			throw createHttpError.Unauthorized('Not authorized, please login.');
		}
	} catch (error) {
		next(error);
	}
});

export const verifiedOnly = asyncHandler(async (req, res, next) => {
	try {
		if (req.user && req.user.isVerified) {
			next();
		} else {
			throw createHttpError.Unauthorized('Not authorized, account not verified.');
		}
	} catch (error) {
		next(error);
	}
});

export const authorOnly = asyncHandler(async (req, res, next) => {
	try {
		if (req.user.role === 'author' || req.user.role === 'admin') {
			next();
		} else {
			throw createHttpError.Unauthorized('Not authorized as an author.');
		}
	} catch (error) {
		next(error);
	}
});

export const adminOnly = asyncHandler(async (req, res, next) => {
	try {
		if (req.user && req.user.role === 'admin') {
			next();
		} else {
			throw createHttpError.Unauthorized('Not authorized as an admin.');
		}
	} catch (error) {
		next(error);
	}
});
