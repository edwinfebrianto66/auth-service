import bcrypt from 'bcrypt'
import jwt from 'jsonwebtoken'
import db from '../utils/db.js'
import { generateToken, generateRefreshToken } from '../utils/token.js'
import { getUserByEmail, getUserById, updateLastLogin, updateStatusOffline, getUserByUsername } from '../models/user.model.js'
import { getUserPermissions } from '../models/auth_assignment.js'


export const login = async (req, res) => {
	const { username, password } = req.body
	const user = await getUserByUsername(username)

	if (!user) return res.status(401).json({ message: 'Username tidak ditemukan' })
	if (user.blocked_at !== null) return res.status(403).json({ message: 'Akun ini diblokir' })

	const cleanHash = user.password_hash.replace(/^\$2y\$/, '$2a$')
	const match = await bcrypt.compare(password, cleanHash)
	if (!match) return res.status(401).json({ message: 'Password salah' })

	  // 🚨 Tambahkan bagian ini:
	let permissions = []
	if (username === 'admindk')
	{
		permissions = ['*']
	} 
	else 
	{
		const [rows] = await db.execute(
			'SELECT item_name FROM auth_assignment WHERE user_id = ?',[user.id]
		)
		permissions = rows.map(r => r.item_name)
	}

	const token = jwt.sign(
	{
		id: user.id,
		username: user.username,
		permissions // <--- penting!
	},
	process.env.JWT_SECRET,
	{
		expiresIn: '1h' 
	})

	const refreshToken = jwt.sign(
		{ id: user.id },
		process.env.JWT_SECRET,
		{ expiresIn: '7d' }
	)

	await updateLastLogin(user.id)
	res.json({ token, refreshToken })
}



export const logout = async (req, res) => {
  await updateStatusOffline(req.user.id)
  res.clearCookie('refreshToken')
  res.json({ message: 'Berhasil logout' })
}

export const refreshToken = (req, res) => {
  const { refreshToken } = req.body
  if (!refreshToken) return res.status(403).json({ message: 'Token tidak ditemukan' })

  try {
    const user = jwt.verify(refreshToken, process.env.JWT_REFRESH_SECRET)
    const newAccessToken = generateToken(user)
    res.json({ token: newAccessToken })
  } catch (err) {
    return res.status(403).json({ message: 'Refresh token tidak valid' })
  }
}

export const getProfile = async (req, res) => {
  const user = await getUserById(req.user.id)
  const permissions = await getUserPermissions(req.user.id)
  res.json({ ...user, permissions })
}

export const verifyToken = (req, res) => {
  res.json({ valid: true, user: req.user })
}

export const forgotPassword = async (req, res) => {
  const { email } = req.body
  const user = await getUserByEmail(email)
  if (!user) return res.status(404).json({ message: 'Email tidak ditemukan' })

  const token = jwt.sign({ id: user.id }, process.env.JWT_SECRET, { expiresIn: '15m' })
  res.json({ message: 'Gunakan token ini untuk reset password', token })
}

export const resetPassword = async (req, res) => {
  const { token, newPassword } = req.body
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET)
    const hash = await bcrypt.hash(newPassword, 10)
    await db.execute('UPDATE user SET password_hash = ? WHERE id = ?', [hash, decoded.id])
    res.json({ message: 'Password berhasil direset' })
  } catch (err) {
    res.status(403).json({ message: 'Token reset tidak valid / expired' })
  }
}

export const register = async (req, res) => {
  const { username, name, email, password } = req.body
  const hash = await bcrypt.hash(password, 10)

  await db.execute(
    'INSERT INTO user (username, name, email, password_hash, status_online, created_at) VALUES (?, ?, ?, ?, 1, NOW())',
    [username, name, email, hash]
  )

  const user = await getUserByEmail(email)
  const token = generateToken(user)
  const refreshToken = generateRefreshToken(user)

  res.status(201).json({ message: 'Register sukses', token, refreshToken })
}