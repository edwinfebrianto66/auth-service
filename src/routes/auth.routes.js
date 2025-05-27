import express from 'express'
import {
  login,
  register,
  logout,
  refreshToken,
  verifyToken,
  forgotPassword,
  resetPassword,
  updateProfile
} from '../controllers/auth.controller.js'
import { authMiddleware } from '../middlewares/auth.middleware.js'
import { getMe } from '../controllers/auth.controller.js'

const router = express.Router()
router.post('/login', login)
router.post('/register', register)
router.post('/logout', authMiddleware, logout)
router.post('/refresh-token', refreshToken)
router.get('/verify-token', authMiddleware, verifyToken)
router.post('/forgot-password', authMiddleware, forgotPassword)
router.get('/me', authMiddleware, getMe)
router.put('/profile', authMiddleware, updateProfile)
router.post('/reset-password', authMiddleware, resetPassword)


export default router
