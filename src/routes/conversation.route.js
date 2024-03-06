import express from 'express';
import trimRequest from 'trim-request';
import { protect } from '../middlewares/authMiddleware.js';
import { createGroup, create_open_conversation, getConversations } from '../controllers/conversation.controller.js';
const router = express.Router();

router.route('/').post(trimRequest.all, protect, create_open_conversation);
router.route('/').get(trimRequest.all, protect, getConversations);
router.route('/group').post(trimRequest.all, protect, createGroup);

export default router;
