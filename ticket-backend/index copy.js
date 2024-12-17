const express = require("express");
const mongoose = require("mongoose");
const bodyParser = require("body-parser");
const cors = require("cors");
const multer = require("multer");
const path = require("path");
const bcrypt = require("bcrypt");
const QRCode = require("qrcode");
const { v4: uuidv4 } = require("uuid");
const nodemailer = require("nodemailer");
const fs = require("fs");
const jwt = require("jsonwebtoken");
const crypto = require('crypto');

// Initialize app
const app = express();
app.use(bodyParser.json());
app.use(cors());
const JWT_SECRET = "your-secret-key";

// Middleware to protect routes
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];

  if (!token) {
    return res.status(401).json({ message: "Authentication token required" });
  }

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({ message: "Invalid or expired token" });
    }
    req.user = user;
    next();
  });
};

// Setup static file serving
app.use("/uploads", express.static("uploads"));
app.use("/qrcodes", express.static("qrcodes"));

// Ensure directories exist
const uploadsDir = path.join(__dirname, "uploads");
const qrcodesDir = path.join(__dirname, "qrcodes");

if (!fs.existsSync(uploadsDir)) {
  fs.mkdirSync(uploadsDir);
}

if (!fs.existsSync(qrcodesDir)) {
  fs.mkdirSync(qrcodesDir);
}

// Setup multer for file uploads
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, "uploads");
  },
  filename: (req, file, cb) => {
    cb(null, Date.now() + path.extname(file.originalname));
  },
});

const upload = multer({ storage });

// Connect to MongoDB
mongoose
  .connect("mongodb://localhost:27017/eventDB")
  .then(() => {
    console.log("Connected to MongoDB");
  })
  .catch((error) => {
    console.error("MongoDB connection error:", error);
  });

// Define User schema
const userSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  email: { type: String, required: true, unique: true },
});

const User = mongoose.model("User", userSchema);

// Define Ticket schema
const ticketSchema = new mongoose.Schema({
  type: { type: String, required: true },
  price: { type: Number, required: true, min: 0 },
  quantity: { type: Number, required: true, min: 1 },
});

// Define Event schema
const eventSchema = new mongoose.Schema({
  title: { type: String, required: true },
  date: { type: Date, required: true },
  location: { type: String, required: true },
  description: { type: String, required: true },
  image: { type: String, required: true },
  tickets: [ticketSchema],
});

const Event = mongoose.model("Event", eventSchema);

// Define Booking schema
const bookingSchema = new mongoose.Schema({
  eventId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "Event",
    required: true,
  },
  email: { type: String, required: true },
  ticketType: { type: String, required: true },
  quantity: { type: Number, required: true },
  totalPrice: { type: Number, required: true },
  bookingDate: { type: Date, default: Date.now },
  ticketId: { type: String, required: true, unique: true },
  qrCode: { type: String, required: true },
});

const Booking = mongoose.model("Booking", bookingSchema);

// Configure nodemailer
const transporter = nodemailer.createTransport({
  service: "gmail",
  auth: {
    user: "rosmengheang168@gmail.com", // Replace with your email
    pass: "ntrd ybvi tdjg yusk", // Replace with your app password
  },
});

// Helper function to format date
function formatDate(date) {
  const options = {
    weekday: "long",
    year: "numeric",
    month: "long",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  };
  return new Date(date).toLocaleDateString("en-US", options);
}

// Add ABA PayWay constants
const ABA_PAYWAY_API_URL = 'https://checkout-sandbox.payway.com.kh/api/payment-gateway/v1/payments/purchase';
const ABA_PAYWAY_API_KEY = 'your-api-key';
const ABA_PAYWAY_MERCHANT_ID = 'your-merchant-id';

// Add helper function for hash generation
function getHash(str) {
  const hmac = crypto.createHmac('sha512', ABA_PAYWAY_API_KEY);
  hmac.update(str);
  return hmac.digest('base64');
}

// Add new endpoint for payment initialization
app.post('/api/payment/initialize', async (req, res) => {
  try {
    const { eventId, ticketType, quantity, email, totalAmount } = req.body;
    
    const req_time = Math.floor(Date.now() / 1000);
    const transactionId = `TKT-${req_time}-${eventId}`;
    
    // Create items array for PayWay
    const items = Buffer.from(JSON.stringify([
      { 
        name: ticketType,
        quantity: quantity.toString(),
        price: (totalAmount / quantity).toFixed(2)
      }
    ])).toString('base64');

    const shipping = '0.00';
    const currency = 'USD';
    const type = 'purchase';
    const return_params = JSON.stringify({
      eventId,
      ticketType,
      quantity,
      email,
      transactionId
    });

    // Generate hash
    const hash = getHash(
      req_time + 
      ABA_PAYWAY_MERCHANT_ID + 
      transactionId + 
      totalAmount.toFixed(2) + 
      items + 
      shipping + 
      email + 
      type + 
      currency + 
      return_params
    );

    // Create payment form data
    const paymentData = {
      hash,
      tran_id: transactionId,
      amount: totalAmount.toFixed(2),
      items,
      email,
      shipping,
      currency,
      type,
      merchant_id: ABA_PAYWAY_MERCHANT_ID,
      req_time,
      return_params,
      continue_success_url: `${process.env.FRONTEND_URL}/dashboard`,
      return_url: `${process.env.FRONTEND_URL}/payment/callback`
    };

    res.json({ 
      paymentUrl: ABA_PAYWAY_API_URL,
      paymentData 
    });

  } catch (error) {
    console.error('Payment initialization error:', error);
    res.status(500).json({ message: 'Failed to initialize payment' });
  }
});

// Add payment callback endpoint
app.post('/api/payment/callback', async (req, res) => {
  try {
    const { tran_id, status } = req.body;
    
    if (status === 'SUCCESS') {
      // Process the successful payment
      // Create booking, generate ticket, etc.
      res.redirect('/dashboard');
    } else {
      res.redirect('/payment-failed');
    }
  } catch (error) {
    console.error('Payment callback error:', error);
    res.status(500).json({ message: 'Payment processing failed' });
  }
});

// API Routes

// User signup
app.post("/api/signup", async (req, res) => {
  const { username, password, email } = req.body;

  try {
    const existingUser = await User.findOne({ username });
    if (existingUser) {
      return res.status(400).json({ message: "Username already exists" });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = new User({
      username,
      password: hashedPassword,
      email,
    });
    await newUser.save();

    // Generate JWT token for automatic login after signup
    const token = jwt.sign(
      { id: newUser._id, username: newUser.username },
      JWT_SECRET,
      { expiresIn: "24h" },
    );

    res.status(201).json({
      message: "User created successfully",
      token: token,
    });
  } catch (error) {
    res.status(400).json({ message: error.message });
  }
});

// User login
app.post("/api/login", async (req, res) => {
  try {
    const user = await User.findOne({ username: req.body.username });
    // ... password validation ...

    const token = jwt.sign(
      {
        id: user._id,
        username: user.username,
        email: user.email, // Include email in token
      },
      JWT_SECRET,
      { expiresIn: "24h" },
    );

    res.json({
      message: "Login successful",
      username: user.username,
      email: user.email, // Include email in response
      token: token,
    });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

// Get single event
app.get("/api/events/:id", authenticateToken, async (req, res) => {
  try {
    const event = await Event.findById(req.params.id);
    if (!event) {
      return res.status(404).json({ message: "Event not found" });
    }
    res.json(event);
  } catch (error) {
    console.error('Error fetching event:', error);
    res.status(500).json({ message: "Error fetching event details" });
  }
});

// Create event
// Create event endpoint with authentication and error handling
app.post(
  "/api/events",
  authenticateToken,
  upload.single("image"),
  async (req, res) => {
    try {
      // Log the received data for debugging
      console.log("Request body:", req.body);
      console.log("File:", req.file);

      const { title, date, location, description, tickets } = req.body;

      // Validate required fields
      if (!title || !date || !location || !description) {
        return res.status(400).json({
          message: "Missing required fields",
          required: ["title", "date", "location", "description"],
        });
      }

      // Validate and parse tickets
      let parsedTickets = [];
      if (tickets) {
        try {
          parsedTickets =
            typeof tickets === "string" ? JSON.parse(tickets) : tickets;

          // Validate ticket structure
          if (!Array.isArray(parsedTickets)) {
            return res
              .status(400)
              .json({ message: "Tickets must be an array" });
          }

          // Validate each ticket
          for (const ticket of parsedTickets) {
            if (!ticket.type || !ticket.price || !ticket.quantity) {
              return res.status(400).json({
                message: "Each ticket must have type, price, and quantity",
                received: ticket,
              });
            }
          }
        } catch (error) {
          return res.status(400).json({
            message: "Invalid tickets format",
            error: error.message,
          });
        }
      }

      // Validate file upload
      if (!req.file) {
        return res.status(400).json({ message: "Image is reqsuired" });
      }

      // Create new event with validated data
      const newEvent = new Event({
        title,
        date: new Date(date),
        location,
        description,
        image: req.file.path.replace(/\\/g, "/"),
        tickets: parsedTickets,
      });

      // Save event and handle response
      const savedEvent = await newEvent.save();
      console.log("Event saved successfully:", savedEvent);

      res.status(201).json({
        message: "Event created successfully",
        event: savedEvent,
      });
    } catch (error) {
      console.error("Error creating event:", error);
      res.status(500).json({
        message: "Failed to create event",
        error: error.message,
      });
    }
  },
);

// Get all events
app.get("/api/events", async (req, res) => {
  try {
    const events = await Event.find().sort({ date: 1 });
    res.json(events);
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

// Get single event


// Get ticket by ID
// Remove or comment out this duplicate route
// app.get("/api/tickets/:ticketId", async (req, res) => { ... });

// Keep and modify this route
app.get("/api/tickets/:id", authenticateToken, async (req, res) => {
  try {
    const booking = await Booking.findOne({ ticketId: req.params.id })
      .populate('eventId')
      .exec();
    
    if (!booking) {
      return res.status(404).json({ message: "Ticket not found" });
    }

    // Verify the user has access to this ticket
    if (booking.email !== req.user.email) {
      return res.status(403).json({ message: "Unauthorized access to ticket" });
    }

    res.json(booking);
  } catch (error) {
    console.error('Error fetching ticket:', error);
    res.status(500).json({ message: "Error fetching ticket details" });
  }
});

// Get all tickets for a user
app.get("/api/bookings/:email", authenticateToken, async (req, res) => {
  try {
    if (req.user.email !== req.params.email) {
      return res.status(403).json({ message: "Unauthorized access" });
    }

    const bookings = await Booking.find({ email: req.params.email })
      .populate('eventId')
      .sort({ bookingDate: -1 });

    res.json(bookings);
  } catch (error) {
    console.error('Error fetching bookings:', error);
    res.status(500).json({ message: error.message });
  }
});

// Create booking
app.post("/api/bookings", async (req, res) => {
  const { eventId, email, ticketType, quantity } = req.body;

  try {
    const event = await Event.findById(eventId);
    if (!event) {
      return res.status(404).json({ message: "Event not found" });
    }

    const ticket = event.tickets.find((t) => t.type === ticketType);
    if (!ticket) {
      return res.status(404).json({ message: "Ticket type not found" });
    }

    const ticketId = uuidv4();
    const qrData = JSON.stringify({
      ticketId,
      eventId,
      ticketType,
      quantity,
    });

    // Generate QR code and save it to file
    const qrCodeFileName = `qr-${ticketId}.png`;
    const qrCodePath = path.join(qrcodesDir, qrCodeFileName);

    await QRCode.toFile(qrCodePath, qrData);

    const totalPrice = ticket.price * quantity;

    const booking = new Booking({
      eventId,
      email,
      ticketType,
      quantity,
      totalPrice,
      ticketId,
      qrCode: `/qrcodes/${qrCodeFileName}`,
    });

    await booking.save();

    // Email template
    const emailTemplate = `
      <!DOCTYPE html>
      <html>
      <head>
        <style>
          body {
            font-family: 'Arial', sans-serif;
            line-height: 1.8;
            color: #333;
            background-color: #f5f5f5;
            margin: 0;
            padding: 0;
          }
          .container {
            max-width: 600px;
            margin: 40px auto;
            padding: 20px;
          }
          .ticket {
            background: white;
            border-radius: 15px;
            box-shadow: 0 8px 20px rgba(0, 0, 0, 0.1);
            overflow: hidden;
          }
          .ticket-header {
            background: linear-gradient(135deg, #4F46E5, #2563EB);
            color: white;
            padding: 25px;
            text-align: center;
          }
          .ticket-title {
            font-size: 28px;
            font-weight: bold;
            margin: 0;
            letter-spacing: 0.5px;
          }
          .ticket-date {
            opacity: 0.9;
            margin-top: 12px;
            font-size: 18px;
          }
          .event-image-container {
            width: 100%;
            height: 300px;
            overflow: hidden;
            position: relative;
          }
          .event-image {
            width: 100%;
            height: 100%;
            object-fit: cover;
            display: block;
          }
          .ticket-body {
            padding: 32px;
          }
          .ticket-info {
            display: flex;
            justify-content: space-between;
            margin-bottom: 24px;
            padding-bottom: 24px;
            border-bottom: 1px solid #eee;
            gap: 40px;
          }
          .info-label {
            color: #666;
            font-size: 16px;
            margin-bottom: 8px;
            text-transform: uppercase;
            letter-spacing: 1px;
          }
          .info-value {
            font-weight: bold;
            font-size: 18px;
            color: #1a1a1a;
          }
          .qr-section {
            text-align: center;
            padding: 32px;
            background: #f8fafc;
            border-radius: 0 0 15px 15px;
            border-top: 2px dashed #e5e7eb;
          }
          .qr-code {
            max-width: 200px;
            margin: 0 auto 16px;
            padding: 16px;
            background: white;
            border-radius: 8px;
            box-shadow: 0 2px 8px rgba(0, 0, 0, 0.05);
          }
          .qr-text {
            color: #4b5563;
            font-size: 16px;
            margin-top: 16px;
          }
          .ticket-footer {
            text-align: center;
            margin-top: 32px;
            color: #666;
            font-size: 15px;
            line-height: 1.8;
          }
          .highlight {
            color: #4F46E5;
            font-weight: bold;
          }
        </style>
      </head>
      <body>
        <div class="container">
          <div class="ticket">
            <div class="ticket-header">
              <h1 class="ticket-title">${event.title}</h1>
              <div class="ticket-date">${formatDate(event.date)}</div>
            </div>

            <div class="event-image-container">
              <img src="cid:eventImage" alt="${event.title}" class="event-image">
            </div>

            <div class="ticket-body">
              <div class="ticket-info">
                <div>
                  <div class="info-label">Location</div>
                  <div class="info-value">${event.location}</div>
                </div>
                <div>
                  <div class="info-label">Ticket Type</div>
                  <div class="info-value">${ticketType}</div>
                </div>
              </div>

              <div class="ticket-info">
                <div style="margin-right: 40px;">
                  <div class="info-label">Quantity</div>
                  <div class="info-value">${quantity}</div>
                </div>
                <div>
                  <div class="info-label">Total Price</div>
                  <div class="info-value">$${totalPrice.toFixed(2)}</div>
                </div>
              </div>

              <div class="ticket-info" style="margin-bottom: 0; border-bottom: none;">
                <div>
                  <div class="info-label">Ticket ID</div>
                  <div class="info-value">${ticketId}</div>
                </div>
              </div>
            </div>

            <div class="qr-section">
              <img src="cid:qrcode" alt="QR Code" class="qr-code">
              <p class="qr-text">Scan this QR code at the event entrance</p>
            </div>
          </div>

          <div class="ticket-footer">
            <p>Thank you for your purchase! <span class="highlight">#${ticketId}</span></p>
            <p>Please keep this ticket safe and present it at the event.</p>
            <p>For any questions, please contact our support team.</p>
          </div>
        </div>
      </body>
      </html>
    `;

    const mailOptions = {
      from: process.env.GMAIL,
      to: email,
      subject: `Your Ticket for ${event.title}`,
      html: emailTemplate,
      attachments: [
        {
          filename: 'qrcode.png',
          path: qrCodePath,
          cid: 'qrcode'
        },
        {
          filename: 'event-image.jpg',
          path: path.join(__dirname, event.image), // Assuming event.image is the file path
          cid: 'eventImage'
        }
      ]
    };

    await transporter.sendMail(mailOptions);

    res.status(201).json({
      message: "Booking successful",
      booking,
      emailSent: true,
    });
  } catch (error) {
    console.error("Booking error:", error);
    res
      .status(500)
      .json({ message: "Error processing booking", error: error.message });
  }
});

// Error handling middleware
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({ message: "Something went wrong!" });
});

// Start server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});
