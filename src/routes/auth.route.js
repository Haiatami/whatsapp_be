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
	loginStatus,
	upgradeUser,
	sendAutomatedEmail,
	sendVerificationEmail,
	verifyUser,
	forgotPassword,
	resetPassword,
} from '../controllers/auth.controller.js';
const router = express.Router();

router.route('/register').post(trimRequest.all, registerUser);
router.route('/login').post(trimRequest.all, loginUser);
router.route('/logout').get(trimRequest.all, logoutUser);
router.route('/getUser').get(trimRequest.all, protect, getUser);
router.route('/updateUser').patch(trimRequest.all, protect, updateUser);
router.route('/:id').delete(trimRequest.all, protect, adminOnly, deleteUser);
router.route('/getUsers').get(trimRequest.all, protect, authorOnly, getUsers);
router.route('/loginStatus').get(trimRequest.all, loginStatus);
router.route('/upgradeUser').post(trimRequest.all, protect, adminOnly, upgradeUser);
router.route('/sendAutomatedEmail').post(trimRequest.all, protect, sendAutomatedEmail);
router.route('/sendVerificationEmail').post(trimRequest.all, protect, sendVerificationEmail);
router.route('/verifyUser/:verificationToken').patch(trimRequest.all, verifyUser);
router.route('/forgotPassword').post(trimRequest.all, forgotPassword);
router.route('/resetPassword/:resetToken').patch(trimRequest.all, resetPassword);

export default router;
