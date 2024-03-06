import express from 'express';
import trimRequest from 'trim-request';
import { protect, adminOnly, authorOnly } from '../middlewares/authMiddleware.js';
import {
	registerUser,
	loginUser,
	logoutUser,
	getUser,
	updateUser,
	deleteUser,
	getUsers,
} from '../controllers/auth.controller.js';
const router = express.Router();

router.route('/register').post(trimRequest.all, registerUser);
router.route('/login').post(trimRequest.all, loginUser);
router.route('/logout').get(trimRequest.all, logoutUser);
router.route('/getUser').get(trimRequest.all, protect, getUser);
router.route('/updateUser').patch(trimRequest.all, protect, updateUser);
router.route('/:id').delete(trimRequest.all, protect, adminOnly, deleteUser);
router.route('/getUsers').get(trimRequest.all, protect, authorOnly, getUsers);

export default router;
