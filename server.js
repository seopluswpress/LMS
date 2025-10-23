import express from 'express';
import mongoose from 'mongoose';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import cors from 'cors';
import dotenv from 'dotenv';
import nodemailer from 'nodemailer';
import axios from 'axios';
import crypto from 'crypto';


dotenv.config();
const app = express();
app.use(express.json());
// Define the allowed origins for CORS
const allowedOrigins = [
  'http://localhost:3000',
  'http://localhost:5173',
  'https://smb-lms.vercel.app'
];

app.use(cors({
  origin: function (origin, callback) {
    if (!origin) return callback(null, true);
    
    if (allowedOrigins.indexOf(origin) === -1) {
      const msg = 'The CORS policy for this site does not allow access from the specified Origin.';
      return callback(new Error(msg), false);
    }
    return callback(null, true);
  },
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS','PATCH'],
  credentials: true,
}));

// ======================
// MongoDB Models
// ======================

const userSchema = new mongoose.Schema({
  username: String,
  email: String,
  role: String,
  courseInterest: {
    type: String,
    default: 'General'
  },
  courses: [{ type: mongoose.Schema.Types.ObjectId, ref: 'Course' }],
  resetPasswordToken: String,
  resetPasswordExpires: Date,
  // OTP fields
  otp: String,
  otpExpires: Date,
});


const sectionSchema = new mongoose.Schema({
  title: { type: String, required: true },
  youtubeUrl: { type: String, required: true },
  context: { type: String, default: '' },
});

const courseSchema = new mongoose.Schema({
  title: { type: String, required: true },
  sections: [sectionSchema],
  description: { type: String },
  is_published: { type: Boolean, default: false },
  courseType: {
    type: String,
    required: true,
    trim: true,
    index: true,
  },
});

const courseHistorySchema = new mongoose.Schema({
  user: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  course: { type: mongoose.Schema.Types.ObjectId, ref: 'Course' },
  watchedAt: { type: Date, default: Date.now },
});

const User = mongoose.model('User', userSchema);
const Course = mongoose.model('Course', courseSchema);
const CourseHistory = mongoose.model('CourseHistory', courseHistorySchema);

// ======================
// Middleware
// ======================

const authMiddleware = async (req, res, next) => {
  const token = req.headers['authorization']?.split(' ')[1];
  if (!token) return res.status(401).send('No token provided');

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = await User.findById(decoded.id);
    if (!req.user) throw new Error('User not found');
    next();
  } catch (err) {
    res.status(401).send('Unauthorized: ' + err.message);
  }
};

// ======================
// Helper Functions
// ======================

async function triggerWelcomeEmail(email, username) {
  if (!process.env.PYTHON_EMAIL_SERVICE_URL || !process.env.INTERNAL_API_KEY) {
    console.error('❌ Email service environment variables not set. Skipping email dispatch.');
    return;
  }

  console.log(`➡️  Dispatching welcome email task to Python service for: ${email}`);
  
  try {
    const response = await axios.post(
      `${process.env.PYTHON_EMAIL_SERVICE_URL}/send-welcome-email`,
      {
        email: email,
        username: username,
      },
      {
        headers: {
          'Content-Type': 'application/json',
          'x-internal-api-key': process.env.INTERNAL_API_KEY,
        },
        timeout: 10000,
      }
    );
    
    console.log(`✅ Python service accepted the email task for ${email}. Response:`, response.data.message);

  } catch (error) {
    console.error(`❌❌ CRITICAL: Failed to dispatch email task for ${email}. Error:`, error.message);
    if (error.response) {
      console.error('Error Details from Python Service:', error.response.data);
      console.error('HTTP Status from Python Service:', error.response.status);
    } else if (error.request) {
      console.error('No response received from the email service. It might be down or unreachable.');
    } else {
      console.error('Axios request setup error:', error.message);
    }
  }
}

// ======================
// NEW: OTP Email Function
// ======================
async function sendOTPEmail(email, username, otp) {
  if (!process.env.PYTHON_EMAIL_SERVICE_URL || !process.env.INTERNAL_API_KEY) {
    console.error('❌ Email service environment variables not set. Cannot send OTP.');
    return;
  }

  console.log(`➡️  Dispatching OTP email to Python service for: ${email}`);
  
  try {
    await axios.post(
      `${process.env.PYTHON_EMAIL_SERVICE_URL}/send-otp-email`,
      {
        email: email,
        username: username,
        otp: otp,
      },
      {
        headers: {
          'Content-Type': 'application/json',
          'x-internal-api-key': process.env.INTERNAL_API_KEY,
        },
        timeout: 10000,
      }
    );
    
    console.log(`✅ OTP email sent successfully to ${email}`);

  } catch (error) {
    console.error(`❌ Failed to send OTP email to ${email}. Error:`, error.message);
    if (error.response) {
      console.error('Error Details:', error.response.data);
      console.error('HTTP Status:', error.response.status);
    }
  }
}

// ======================
// Routes
// ======================

// Register user
app.post('/api/register', async (req, res) => {
  try {
    const { username, email, password, role, courseInterest } = req.body;
    console.log('📩 Incoming registration:', { username, email, role, courseInterest });

    const existingUser = await User.findOne({ email });
    if (existingUser) {
      console.log('⚠️ User already exists:', email);
      return res.status(400).json({ message: 'User already exists' });
    }

    const newUser = await User.create({
      username: username || email.split('@')[0],
      email,
      role: role || 'user',
      courseInterest: courseInterest || 'General',
    });
    console.log('✅ User created in MongoDB:', newUser.email, 'with interest:', newUser.courseInterest);

    const token = jwt.sign(
      { id: newUser._id, role: newUser.role },
      process.env.JWT_SECRET,
      { expiresIn: '1h' }
    );

    res.status(201).json({
      message: 'User registered successfully',
      token,
      user: { 
        id: newUser._id, 
        username: newUser.username, 
        email: newUser.email, 
        role: newUser.role, 
        courseInterest: newUser.courseInterest
      },
    });

    triggerWelcomeEmail(newUser.email, newUser.username)
        .catch(err => {
            console.error("Non-blocking email dispatch process completed with an error.");
        });

  } catch (error) {
    console.error('💥 Critical error during registration process:', error);
    if (!res.headersSent) {
      res.status(500).json({ message: 'Internal server error', error: error.message });
    }
  }
});

// ======================
// NEW: Request OTP for Login
// ======================
app.post('/api/request-otp', async (req, res) => {
  try {
    const { email } = req.body;
    
    if (!email) {
      return res.status(400).json({ message: 'Email is required' });
    }

    const user = await User.findOne({ email });
    if (!user) {
      return res.status(400).json({ message: 'User not found. Please register first.' });
    }

    // Generate 6-digit OTP
    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    
    // Store OTP with 5-minute expiration
    user.otp = otp;
    user.otpExpires = Date.now() + 5 * 60 * 1000; // 5 minutes
    await user.save();

    // Send OTP via email service
    await sendOTPEmail(user.email, user.username, otp);
    
    // For development/testing (REMOVE IN PRODUCTION!)
    console.log(`🔐 OTP for ${email}: ${otp}`);

    res.json({ message: 'OTP sent to your email. Valid for 5 minutes.' });
  } catch (error) {
    console.error('Request OTP error:', error);
    res.status(500).json({ message: 'An error occurred', error: error.message });
  }
});

// ======================
// UPDATED: Login with OTP (replaces password-based login)
// ======================
app.post('/api/login', async (req, res) => {
  try {
    const { email, otp } = req.body;
    
    if (!email || !otp) {
      return res.status(400).json({ message: 'Email and OTP are required' });
    }

    const user = await User.findOne({ email });
    if (!user) {
      return res.status(400).json({ message: 'Invalid credentials' });
    }

    // Check if OTP exists
    if (!user.otp || !user.otpExpires) {
      return res.status(400).json({ message: 'No OTP requested. Please request OTP first.' });
    }

    // Check if OTP expired
    if (Date.now() > user.otpExpires) {
      return res.status(400).json({ message: 'OTP expired. Please request a new one.' });
    }

    // Verify OTP
    if (user.otp !== otp) {
      return res.status(400).json({ message: 'Invalid OTP' });
    }

    // Clear OTP after successful verification
    user.otp = undefined;
    user.otpExpires = undefined;
    await user.save();

    if (!process.env.JWT_SECRET) {
      console.error('JWT_SECRET is not defined in environment variables');
      return res.status(500).json({ message: 'Server configuration error' });
    }

    // Generate JWT token
    const token = jwt.sign(
      { 
        id: user._id,
        role: user.role,
        email: user.email
      },
      process.env.JWT_SECRET,
      { expiresIn: '1h' }
    );

    console.log(`✅ User ${email} logged in successfully with OTP`);

    res.json({ 
      token, 
      message: 'Login successful',
      user: {
        id: user._id,
        username: user.username,
        email: user.email,
        role: user.role,
        courseInterest: user.courseInterest
      }
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ message: 'An error occurred during login', error: error.message });
  }
});

// Request password reset
app.post('/api/request-password-reset', async (req, res) => {
  try {
    const { email } = req.body;
    const user = await User.findOne({ email });

    if (!user) {
      console.log(`⚠️ Password reset request for non-existent email: ${email}`);
      return res.json({ message: 'If an account with that email exists, a password reset link has been sent.' });
    }

    const resetToken = crypto.randomBytes(32).toString('hex');

    user.resetPasswordToken = resetToken;
    user.resetPasswordExpires = Date.now() + 3600000; // 1 hour
    await user.save();

    const resetUrl = `${process.env.FRONTEND_URL}/reset-password/${resetToken}`;

    console.log(`🔗 Password reset link for ${email}: ${resetUrl}`);

    if (process.env.PYTHON_EMAIL_SERVICE_URL && process.env.INTERNAL_API_KEY) {
      console.log(`➡️  Dispatching password reset email task to Python service for: ${email}`);
      try {
        await axios.post(
          `${process.env.PYTHON_EMAIL_SERVICE_URL}/send-password-reset-email`,
          {
            email: user.email,
            username: user.username,
            reset_url: resetUrl
          },
          {
            headers: {
              'Content-Type': 'application/json',
              'x-internal-api-key': process.env.INTERNAL_API_KEY
            },
            timeout: 10000
          }
        );
        console.log(`✅ Python service accepted the password reset task for ${email}.`);
      } catch (error) {
        console.error(`❌❌ CRITICAL: Failed to dispatch password reset email for ${email}. Error:`, error.message);
        if (error.response) {
          console.error('Error Details from Python Service:', error.response.data);
          console.error('HTTP Status from Python Service:', error.response.status);
        } else if (error.request) {
          console.error('No response received from the email service. It might be down or unreachable.');
        } else {
          console.error('Axios request setup error:', error.message);
        }
      }
    } else {
      console.log('⚠️ No Python email service configured — email not sent.');
    }

    res.json({ message: 'If an account with that email exists, a password reset link has been sent.' });

  } catch (error) {
    console.error('Error in top-level request-password-reset logic:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
});

// Reset password
app.post('/api/reset-password/:token', async (req, res) => {
  try {
    const { token } = req.params;
    const { password } = req.body;

    const user = await User.findOne({
      resetPasswordToken: token,
      resetPasswordExpires: { $gt: Date.now() },
    });

    if (!user) {
      return res.status(400).json({ message: 'Invalid or expired token.' });
    }

    const hashed = await bcrypt.hash(password, 10);

    user.password = hashed;
    user.resetPasswordToken = undefined;
    user.resetPasswordExpires = undefined;
    await user.save();

    res.json({ message: 'Password updated successfully.' });
  } catch (error) {
    console.error('Error resetting password:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
});

// Enroll in a course
app.post('/api/enroll', authMiddleware, async (req, res) => {
  try {
    const { courseId } = req.body;
    const user = req.user;

    if (!courseId) {
      return res.status(400).json({ message: 'Course ID is required.' });
    }
    
    const course = await Course.findById(courseId);
    if (!course) {
      return res.status(404).json({ message: 'Course not found.' });
    }

    if (user.courses.includes(courseId)) {
      return res.status(400).json({ message: 'Already enrolled in this course.' });
    }

    user.courses.push(courseId);
    await user.save();

    res.json({ message: 'Enrolled successfully.', courses: user.courses });

  } catch (error) {
    console.error('Enrollment error:', error);
    res.status(500).json({ message: 'Internal server error.' });
  }
});

// Add course (admin)
app.post('/api/courses', async (req, res) => {
  try {
    console.log("Received body:", req.body);

    const course = new Course(req.body);
    await course.save();

    res.status(201).json(course);
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: error.message });
  }
});

// Update a course
app.put('/api/courses/:id', authMiddleware, async (req, res) => {
  try {
    const { title, description, sections } = req.body;

    const course = await Course.findById(req.params.id);
    if (!course) {
      return res.status(404).json({ message: 'Course not found' });
    }

    if (req.user.role !== 'admin' && req.user.role !== 'educator') {
      return res.status(403).json({ message: 'Permission denied' });
    }

    course.title = title || course.title;
    course.description = description || course.description;
    course.sections = sections || course.sections;

    await course.save();
    res.json({ message: 'Course updated successfully', course });
  } catch (error) {
    console.error('Error updating course:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
});

// List courses
app.get('/api/courses', authMiddleware, async (req, res) => {
  const courses = await Course.find();
  res.json(courses);
});

// Secure video proxy endpoint
app.get('/api/video/:courseId', authMiddleware, async (req, res) => {
  const course = await Course.findById(req.params.courseId);
  if (!course) return res.status(404).send('Course not found');

  await CourseHistory.create({ user: req.user._id, course: course._id });

  res.json({ url: course.youtubeUrl });
});

// User course history
app.get('/api/history', authMiddleware, async (req, res) => {
  const history = await CourseHistory.find({ user: req.user._id }).populate('course');
  res.json(history);
});

// Delete a course
app.delete('/api/courses/:id', authMiddleware, async (req, res) => {
  try {
    const course = await Course.findById(req.params.id);
    if (!course) {
      return res.status(404).json({ message: 'Course not found' });
    }

    await Course.findByIdAndDelete(req.params.id);
    res.json({ message: 'Course deleted successfully' });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Internal server error' });
  }
});

// Get a single course by ID
app.get('/api/courses/:id', authMiddleware, async (req, res) => {
  try {
    const course = await Course.findById(req.params.id);
    if (!course) {
      return res.status(404).json({ message: 'Course not found' });
    }
    res.json(course);
  } catch (error) {
    console.error('Error fetching course by ID:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
});

app.patch('/api/courses/:id/publish', authMiddleware, async (req, res) => {
  try {
    const { is_published } = req.body;
    
    const course = await Course.findByIdAndUpdate(
      req.params.id,
      { is_published },
      { new: true }
    )

    if (!course) {
      return res.status(404).json({ message: 'Course not found' });
    }
    res.json({ message: 'Course status updated successfully', course });
  } catch (error) {
    console.error('Error updating course status:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
});

app.patch('/api/courses/:id/unpublish', authMiddleware, async (req, res) => {
  try {
    const { is_published } = req.body;
    
    const course = await Course.findByIdAndUpdate(
      req.params.id,
      { is_published },
      { new: false }
    )

    if (!course) {
      return res.status(404).json({ message: 'Course not found' });
    }
    res.json({ message: 'Course status updated successfully', course });
  } catch (error) {
    console.error('Error updating course status:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
});

// Get all users (Admin only)
app.get('/api/users', authMiddleware, async (req, res) => {
  try {
    const users = await User.find().select('-password -otp');
    res.json(users);
  } catch (error) {
    console.error('Error fetching users:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
});

// ======================
// Connect MongoDB & Start
// ======================

mongoose.connect(process.env.MONGO_URI)
  .then(() => {
    console.log('MongoDB connected');
    app.listen(process.env.PORT, () => console.log(`Server running on ${process.env.PORT}`));
  })
  .catch(err => console.log(err));
