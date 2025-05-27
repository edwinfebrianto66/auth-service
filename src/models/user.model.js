import db from '../utils/db.js'

export const getUserByEmail = async (email) => {
  const [rows] = await db.execute(
    `SELECT id, username, name, email, password_hash, blocked_at, last_login_at FROM user WHERE email = ?`,
    [email]
  )
  return rows[0]
}

export const getUserById = async (id) => {
  const [rows] = await db.execute('SELECT * FROM user WHERE id = ?', [id])
  return rows[0]
}

export const updateLastLogin = async (id) => {
  await db.execute(
    `UPDATE user SET last_login_at = NOW(), status_online = 1 WHERE id = ?`,
    [id]
  )
}

export const getUserByUsername = async (username) => {
  const [rows] = await db.execute(
    `SELECT id, username, name, email, password_hash, blocked_at, last_login_at FROM user WHERE username = ?`,
    [username]
  )
  return rows[0]
}



export const updateStatusOffline = async (id) => {
  await db.execute(
    `UPDATE user SET status_online = 0 WHERE id = ?`,
    [id]
  )
}
