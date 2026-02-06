const express = require('express')
const cors = require('cors')
const jwt = require('jsonwebtoken')
const bcrypt = require('bcryptjs')
const axios = require('axios')

const app = express()
app.use(cors())
app.use(express.json())

const JWT_SECRET = process.env.JWT_SECRET || 'jwt_secret'
const JWT_EXPIRY = '7d'

const PAYMOB_API_KEY = process.env.PAYMOB_API_KEY || ''
const PAYMOB_INTEGRATION_ID = process.env.PAYMOB_INTEGRATION_ID || ''
const PAYMOB_IFRAME_ID = process.env.PAYMOB_IFRAME_ID || ''

let users = []
let listings = []
let rentals = []
let payments = []
let ratings = []
let otpCodes = {}

function generateOTP() {
  return Math.floor(100000 + Math.random() * 900000).toString()
}

function generateToken(userId) {
  return jwt.sign({ userId }, JWT_SECRET, { expiresIn: JWT_EXPIRY })
}

function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization']
  const token = authHeader && authHeader.split(' ')[1]
  if (!token) return res.status(401).json({ error: 'Unauthorized' })
  jwt.verify(token, JWT_SECRET, (err, decoded) => {
    if (err) return res.status(403).json({ error: 'Forbidden' })
    const user = users.find(u => u.userId === decoded.userId)
    if (!user) return res.status(404).json({ error: 'User not found' })
    req.user = user
    next()
  })
}

async function getPaymobAuthToken() {
  const res = await axios.post('https://accept.paymob.com/api/auth/tokens', {
    api_key: PAYMOB_API_KEY
  })
  return res.data.token
}

async function createPaymobOrder(authToken, amount, orderId) {
  const res = await axios.post('https://accept.paymob.com/api/ecommerce/orders', {
    auth_token: authToken,
    delivery_needed: false,
    amount_cents: amount * 100,
    currency: 'EGP',
    merchant_order_id: orderId,
    items: []
  })
  return res.data
}

async function getPaymobPaymentKey(authToken, orderData, amount, user) {
  const res = await axios.post('https://accept.paymob.com/api/acceptance/payment_keys', {
    auth_token: authToken,
    amount_cents: amount * 100,
    expiration: 3600,
    order_id: orderData.id,
    billing_data: {
      apartment: 'NA',
      email: user.email,
      floor: 'NA',
      first_name: user.fullName.split(' ')[0] || 'User',
      street: 'NA',
      building: 'NA',
      phone_number: '01000000000',
      shipping_method: 'NA',
      postal_code: 'NA',
      city: 'NA',
      country: 'EG',
      last_name: user.fullName.split(' ')[1] || 'User',
      state: 'NA'
    },
    currency: 'EGP',
    integration_id: PAYMOB_INTEGRATION_ID
  })
  return res.data.token
}

app.post('/api/auth/register', async (req, res) => {
  const { email, password, fullName } = req.body
  if (!email || !password || !fullName) return res.status(400).json({ error: 'Invalid data' })
  if (users.find(u => u.email === email)) return res.status(400).json({ error: 'Exists' })
  const hashed = await bcrypt.hash(password, 10)
  const otp = generateOTP()
  otpCodes[email] = { code: otp, expires: Date.now() + 600000 }
  const user = {
    userId: 'user_' + Date.now(),
    email,
    password: hashed,
    fullName,
    role: 'STUDENT',
    isVerified: false,
    ratingAverage: 0,
    ratingCount: 0
  }
  users.push(user)
  console.log('OTP:', otp)
  res.status(201).json({ message: 'OTP sent' })
})

app.post('/api/auth/verify-otp', (req, res) => {
  const { email, otp } = req.body
  const user = users.find(u => u.email === email)
  if (!user) return res.status(404).json({ error: 'Not found' })
  const record = otpCodes[email]
  if (!record || record.code !== otp || record.expires < Date.now()) {
    return res.status(400).json({ error: 'Invalid OTP' })
  }
  user.isVerified = true
  delete otpCodes[email]
  const token = generateToken(user.userId)
  const { password, ...data } = user
  res.json({ token, user: data })
})

app.post('/api/auth/login', async (req, res) => {
  const { email, password } = req.body
  const user = users.find(u => u.email === email)
  if (!user) return res.status(401).json({ error: 'Invalid' })
  const ok = await bcrypt.compare(password, user.password)
  if (!ok || !user.isVerified) return res.status(401).json({ error: 'Invalid' })
  const token = generateToken(user.userId)
  const { password: p, ...data } = user
  res.json({ token, user: data })
})

app.post('/api/listings', authenticateToken, (req, res) => {
  const { title, description, category, salePrice, isRentable, rentalPricePerDay } = req.body
  const listing = {
    listingId: 'listing_' + Date.now(),
    ownerId: req.user.userId,
    title,
    description,
    category,
    salePrice: salePrice || null,
    isRentable: isRentable || false,
    rentalPricePerDay: rentalPricePerDay || null,
    status: 'AVAILABLE',
    createdAt: new Date()
  }
  listings.push(listing)
  res.status(201).json(listing)
})

app.get('/api/listings', authenticateToken, (req, res) => {
  res.json(listings)
})

app.post('/api/payment/initiate', authenticateToken, async (req, res) => {
  const { listingId, amount, type } = req.body
  const listing = listings.find(l => l.listingId === listingId)
  if (!listing) return res.status(404).json({ error: 'Not found' })
  const orderId = 'order_' + Date.now()
  payments.push({
    orderId,
    listingId,
    userId: req.user.userId,
    amount,
    type,
    status: 'pending'
  })
  const authToken = await getPaymobAuthToken()
  const order = await createPaymobOrder(authToken, amount, orderId)
  const paymentKey = await getPaymobPaymentKey(authToken, order, amount, req.user)
  const url = `https://accept.paymob.com/api/acceptance/iframes/${PAYMOB_IFRAME_ID}?payment_token=${paymentKey}`
  res.json({ paymentUrl: url, orderId })
})

app.post('/api/payment/callback', (req, res) => {
  const { success, order_id } = req.body
  const payment = payments.find(p => p.orderId === order_id)
  if (!payment) return res.status(404).json({ error: 'Not found' })
  payment.status = success ? 'completed' : 'failed'
  res.json({ ok: true })
})

const PORT = process.env.PORT || 5000
app.listen(PORT, () => {
  console.log(`Server running on ${PORT}`)
})
