import express from 'express';
import {
  register,
  login,
  logout,
  forgetPassword,
} from '../../controllers/auth.js';
import { verifyUser } from '../../middlewares/verify-user.js';

const router = express.Router();

router.post('/register', register);
router.post('/login', login);
router.post('/logout', verifyUser, logout);
router.post('/forget-password', forgetPassword);

export default router;
