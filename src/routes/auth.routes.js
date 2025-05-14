import express from 'express'
import {
  login,
  register,
  logout,
  refreshToken,
  getProfile,
  verifyToken,
  forgotPassword,
  resetPassword
} from '../controllers/auth.controller.js'

import { authMiddleware } from '../middlewares/auth.middleware.js'
import { getMe } from '../controllers/auth.controller.js'

const router = express.Router()

router.post('/login', login)
router.post('/register', register)
router.post('/logout', authMiddleware, logout)
router.post('/refresh-token', refreshToken)
router.get('/me', authMiddleware, getProfile)
router.get('/verify-token', authMiddleware, verifyToken)
router.post('/forgot-password', forgotPassword)
router.post('/reset-password', resetPassword)
router.get('/me', authMiddleware, getMe)

export default router
