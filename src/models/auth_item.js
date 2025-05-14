import db from '../utils/db.js'

export const getRoleByName = async (name) => {
  const [rows] = await db.execute('SELECT * FROM auth_item WHERE name = ?', [name])
  return rows[0]
}
