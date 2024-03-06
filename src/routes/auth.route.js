import express from 'express';
import trimRequest from 'trim-request';
import { registerUser, loginUser, logoutUser } from '../controllers/auth.controller.js';
const router = express.Router();

router.route('/register').post(trimRequest.all, registerUser);
router.route('/login').post(trimRequest.all, loginUser);
router.route('/logout').post(trimRequest.all, logoutUser);
export default router;
