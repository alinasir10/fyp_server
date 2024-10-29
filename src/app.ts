import express from 'express'
import cors from 'cors'
import cookieParser from "cookie-parser";

const app = express()

app.use(cors({
  origin: ['http://localhost:3000', '192.168.230.8:3000', '192.168.100.67:3000' ],
  credentials: true
}))

app.use(cookieParser())
app.use(express.json());

import authRoutes from "./routes/authRoutes";

app.get('/', (req, res) => {
  res.send('Hello World');
})
app.use('/api/auth', authRoutes);


export default app;