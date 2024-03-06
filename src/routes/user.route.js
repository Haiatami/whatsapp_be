import express from 'express';
import trimRequest from 'trim-request';
import { searchUsers } from '../controllers/user.controller.js';
import { protect } from '../middlewares/authMiddleware.js';

const router = express.Router();

router.route('/').get(trimRequest.all, protect, searchUsers);
export default router;
