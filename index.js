import express from 'express'
import dotenv from 'dotenv'
import cookieParser from 'cookie-parser'
import cors from 'cors'
import authRoutes from './src/routes/auth.routes.js'

dotenv.config()

const app = express()
app.use(cors())
app.use(express.json())
app.use(cookieParser())

app.use('/auth', authRoutes)

const PORT = process.env.PORT || 4000
app.listen(PORT, () => console.log(`✅ Auth service running on port ${PORT}`))
