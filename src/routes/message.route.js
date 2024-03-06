import express from 'express';
import trimRequest from 'trim-request';
import { protect } from '../middlewares/authMiddleware.js';
import { sendMessage, getMessages } from '../controllers/message.controller.js';

const router = express.Router();

router.route('/').post(trimRequest.all, protect, sendMessage);
router.route('/:convo_id').get(trimRequest.all, protect, getMessages);
export default router;
