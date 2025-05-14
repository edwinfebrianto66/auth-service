import db from '../utils/db.js'

export const getUserPermissions = async (userId) => {
  const [rows] = await db.execute(
    'SELECT item_name FROM auth_assignment WHERE user_id = ?',
    [userId]
  )
  return rows.map(row => row.item_name) // contoh: ['master-customer[R]', 'sales-order[U]']
}
