import { Router } from 'express';

import * as authController from "../controllers/authController";
import {validateSessionMiddleware} from "../middleware";

const router = Router();

router.post('/register', authController.register)
router.post('/login', authController.login)
router.post('/logout', validateSessionMiddleware, authController.logout)
router.post('/verify', validateSessionMiddleware, authController.verifyEmail)
router.post('/resend', validateSessionMiddleware, authController.resendOTP)
router.post('/password', authController.forgotPassword)
router.post('/reset-password', authController.verifyResetToken)
router.post('/reset-password/new', authController.resetPassword)
router.get('/oauth/google', authController.loginGoogle)
router.get('/oauth/google/callback', authController.handleCallbackGoogle)
router.get('/user', validateSessionMiddleware, authController.fetchUserDetails)

router.get('/verify-token', (req, res) => {
  console.log(req.cookies)
  console.log(req.headers)
  res.status(200).json({valid: true})
})

export default router;