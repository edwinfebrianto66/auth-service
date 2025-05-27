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
    const user = jwt.verify(refreshToken, process.env.JWT_SECRET)
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

export const getMe = async (req, res) => {
  const user = await getUserById(req.user.id)
  const permissions = await getUserPermissions(req.user.id)

  if (!user) return res.status(404).json({ message: 'User tidak ditemukan' })

  res.json({
    id: user.id,
    name: user.name,
    username: user.username,
    role: user.role,
    email: user.email,
    phone: user.phone,
    gender: user.gender,
    address: user.address,
    permissions
  })
}
export const updateProfile = async (req, res) => {
  const { name, email, phone, gender, address, nik } = req.body
  const userId = req.user.id

  await db.execute(
    `UPDATE user SET 
      name = ?, email = ?, phone = ?, gender = ?, address = ?, nik = ?
    WHERE id = ?`,
    [name, email, phone, gender, address, nik, userId]
  )

  // Ambil ulang user setelah update
  const [rows] = await db.execute('SELECT * FROM user WHERE id = ?', [userId])
  const updatedUser = rows[0]

  res.json({
    id: updatedUser.id,
    username: updatedUser.username,
    name: updatedUser.name,
    email: updatedUser.email,
    phone: updatedUser.phone,
    gender: updatedUser.gender,
    address: updatedUser.address,
    nik: updatedUser.nik,
    role: updatedUser.role,
    last_login_at: updatedUser.last_login_at,
    status_online: updatedUser.status_online,
    permissions: req.user.permissions || []
  })
}

export const resetPassword = async (req, res) => {
  const userId = req.user.id
  const { oldPassword, newPassword } = req.body

  const [rows] = await db.execute('SELECT password_hash FROM user WHERE id = ?', [userId])
  const user = rows[0]
  if (!user) return res.status(404).json({ message: 'User not found' })

  const match = await bcrypt.compare(oldPassword, user.password_hash.replace(/^\$2y/, '$2a'))
  if (!match) return res.status(400).json({ message: 'Password lama salah' })

  const newHash = await bcrypt.hash(newPassword, 10)
  await db.execute('UPDATE user SET password_hash = ? WHERE id = ?', [newHash, userId])

  return res.json({ success: true, message: 'Password updated' }) // <-- INI PENTING
}

