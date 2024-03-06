import express from 'express';
import trimRequest from 'trim-request';
import { protect, adminOnly, authorOnly } from '../middlewares/authMiddleware.js';
import { registerUser, loginUser, logoutUser, getUser, updateUser } from '../controllers/auth.controller.js';
const router = express.Router();

router.route('/register').post(trimRequest.all, registerUser);
router.route('/login').post(trimRequest.all, loginUser);
router.route('/logout').get(trimRequest.all, logoutUser);
router.route('/getUser').get(trimRequest.all, protect, getUser);
router.route('/updateUser').patch(trimRequest.all, protect, updateUser);

export default router;
