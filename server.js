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
  'http://localhost:3000', // Your local frontend
  'http://localhost:5173',
  'https://your-deployed-frontend-url.com' // IMPORTANT: Replace with your actual frontend URL when you deploy it
];

app.use(cors({
  origin: function (origin, callback) {
    // allow requests with no origin (like mobile apps or curl requests)
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
  password: String,
  role: String,
  courses: [{ type: mongoose.Schema.Types.ObjectId, ref: 'Course' }],
  resetPasswordToken: String,
  resetPasswordExpires: Date,
});


const sectionSchema = new mongoose.Schema({
  title: { type: String, required: true },
  youtubeUrl: { type: String, required: true },
  context: { type: String, default: '' },
});

const courseSchema = new mongoose.Schema({
  title: { type: String, required: true },
  sections: [sectionSchema], // array of sections
  description: { type: String }, // description for the whole course
  is_published: { type: Boolean, default: false },
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
// Routes
// ======================



// Register user // Make sure axios is imported at the top of your file

// ... (keep all your other imports and schema definitions) ...


// =========================================================================
//  NEW HELPER FUNCTION TO CALL THE PYTHON EMAIL SERVICE
// =========================================================================
/**
 * A non-blocking function to trigger the external Python email service.
 * It includes robust error logging for easy debugging.
 * @param {string} email - The recipient's email address.
 * @param {string} username - The recipient's username.
 */
async function triggerWelcomeEmail(email, username) {
  // Check if the required environment variables are configured
  if (!process.env.PYTHON_EMAIL_SERVICE_URL || !process.env.INTERNAL_API_KEY) {
    console.error('❌ Email service environment variables (PYTHON_EMAIL_SERVICE_URL or INTERNAL_API_KEY) are not set. Skipping email dispatch.');
    return;
  }

  console.log(`➡️  Dispatching welcome email task to Python service for: ${email}`);
  
  try {
    // Make a POST request to the Python service
    const response = await axios.post(
      `${process.env.PYTHON_EMAIL_SERVICE_URL}/send-welcome-email`, // The URL of your deployed Python app
      {
        // The JSON payload that the FastAPI service expects
        email: email,
        username: username,
      },
      {
        // The headers, including the secret key for authentication
        headers: {
          'Content-Type': 'application/json',
          'x-internal-api-key': process.env.INTERNAL_API_KEY,
        },
        // Set a reasonable timeout to prevent hanging requests
        timeout: 10000, // 10 seconds
      }
    );
    
    console.log(`✅ Python service accepted the email task for ${email}. Response:`, response.data.message);

  } catch (error) {
    // This detailed error logging is crucial for figuring out what went wrong
    console.error(`❌❌ CRITICAL: Failed to dispatch email task for ${email}. Error:`, error.message);
    if (error.response) {
      // The Python service responded with an error (e.g., 401 Unauthorized, 500 Server Error)
      console.error('Error Details from Python Service:', error.response.data);
      console.error('HTTP Status from Python Service:', error.response.status);
    } else if (error.request) {
      // The request was made but no response was received (e.g., timeout, service is down)
      console.error('No response received from the email service. It might be down or unreachable.');
    } else {
      // Something else went wrong in setting up the request
      console.error('Axios request setup error:', error.message);
    }
    // We do NOT throw an error here, as user registration has already succeeded.
    // This is a background task failure.
  }
}


// =========================================================================
//  UPDATED USER REGISTRATION ROUTE
// =========================================================================

app.post('/api/register', async (req, res) => {
  try {
    const { username, email, password, role } = req.body;
    console.log('📩 Incoming registration:', { username, email, role });

    // Step 1: Check if user exists (Unchanged)
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      console.log('⚠️ User already exists:', email);
      return res.status(400).json({ message: 'User already exists' });
    }

    // Step 2: Hash password (Unchanged)
    const hashed = await bcrypt.hash(password, 10);

    // Step 3: Create user in the database (Unchanged)
    const newUser = await User.create({
      username: username || email.split('@')[0],
      email,
      password: hashed,
      role: role || 'user',
    });
    console.log('✅ User created in MongoDB:', newUser.email);

    // Step 4: Generate JWT token (Unchanged)
    const token = jwt.sign(
      { id: newUser._id, role: newUser.role },
      process.env.JWT_SECRET,
      { expiresIn: '1h' }
    );

    // Step 5: Respond to the client IMMEDIATELY. This makes the registration feel instant.
    // We use status 201 "Created" which is more accurate for a registration.
    res.status(201).json({
      message: 'User registered successfully',
      token,
      user: { id: newUser._id, username: newUser.username, email: newUser.email, role: newUser.role },
    });

    // --- POST-RESPONSE TASK ---
    // Step 6: Trigger the welcome email via the Python service in the background.
    // We do NOT use `await` here. This is a "fire-and-forget" call.
    // The .catch() prevents a potential unhandled promise rejection from crashing the server.
    triggerWelcomeEmail(newUser.email, newUser.username)
        .catch(err => {
            // The error is already logged in detail inside the helper function.
            // This just confirms the non-blocking task finished with an error.
            console.error("Non-blocking email dispatch process completed with an error.");
        });

  } catch (error) {
    console.error('💥 Critical error during registration process:', error);
    if (!res.headersSent) {
      res.status(500).json({ message: 'Internal server error', error: error.message });
    }
  }
});



// Login user
app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;
  const user = await User.findOne({ email });
  if (!user) return res.status(400).send('Invalid credentials');

  const match = await bcrypt.compare(password, user.password);
  if (!match) return res.status(400).send('Invalid credentials');

  const token = jwt.sign({ id: user._id,role: user.role,email: user.email},process.env.JWT_SECRET,{ expiresIn: '1h' });

  res.json({ token });
});

//Request password reset
app.post('/api/request-password-reset', async (req, res) => {
  try {
    const { email } = req.body;
    const user = await User.findOne({ email });

    if (!user) {
      return res.status(400).json({ message: 'No account with that email found.' });
    }

    // Generate secure token
    const resetToken = crypto.randomBytes(32).toString('hex');

    // Set token and expiry (1 hour)
    user.resetPasswordToken = resetToken;
    user.resetPasswordExpires = Date.now() + 3600000; // 1 hour
    await user.save();

    // Construct reset URL
    const resetUrl = `${process.env.FRONTEND_URL}/reset-password/${resetToken}`;

    console.log(`🔗 Password reset link for ${email}: ${resetUrl}`);

    // Option 1: Use Python service
    if (process.env.PYTHON_EMAIL_SERVICE_URL) {
      await axios.post(
  `${process.env.PYTHON_EMAIL_SERVICE_URL}/send-password-reset-email`,
  { email, username: user.username, reset_url: resetUrl },
  { headers: { 'x-internal-api-key': process.env.INTERNAL_API_KEY,
             'Content-Type': 'application/json',} }
);

    } else {
      console.log('⚠️ No Python email service configured — email not sent.');
    }

    res.json({ message: 'Password reset link sent to your email.' });
  } catch (error) {
    console.error('Error in request-password-reset:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
});

// Reset password
app.post('/api/reset-password/:token', async (req, res) => {
  try {
    const { token } = req.params;
    const { password } = req.body;

    // Find user with valid token and unexpired time
    const user = await User.findOne({
      resetPasswordToken: token,
      resetPasswordExpires: { $gt: Date.now() }, // still valid
    });

    if (!user) {
      return res.status(400).json({ message: 'Invalid or expired token.' });
    }

    // Hash new password
    const hashed = await bcrypt.hash(password, 10);

    // Update user password and clear token fields
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



// --- ADD THIS NEW ROUTE ---
// Enroll in a course
app.post('/api/enroll', authMiddleware, async (req, res) => {
  try {
    const { courseId } = req.body;
    const user = req.user;

    if (!courseId) {
      return res.status(400).json({ message: 'Course ID is required.' });
    }
    
    // Check if the course exists
    const course = await Course.findById(courseId);
    if (!course) {
      return res.status(404).json({ message: 'Course not found.' });
    }

    // Check if user is already enrolled
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
    console.log("Received body:", req.body); // Quick test

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

    // Optional: ensure only admin/educator can edit
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

  // Store user course history
  await CourseHistory.create({ user: req.user._id, course: course._id });

  // Return the YouTube URL (or could fetch metadata)
  res.json({ url: course.youtubeUrl });
});

// User course history
// User course history
app.get('/api/history', authMiddleware, async (req, res) => {
  const history = await CourseHistory.find({ user: req.user._id }).populate('course');
  res.json(history);
});

// ADD THIS NEW ROUTE
// Delete a course (assuming only creators/admins can do this)
app.delete('/api/courses/:id', authMiddleware, async (req, res) => {
  try {
    const course = await Course.findById(req.params.id);
    if (!course) {
      return res.status(404).json({ message: 'Course not found' });
    }

    // Optional: Add logic here to check if req.user is the creator of the course
    // For now, we'll assume any authenticated user with access to this route can delete.

    await Course.findByIdAndDelete(req.params.id);
    res.json({ message: 'Course deleted successfully' });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Internal server error' });
  }
});

app.get('/api/courses', authMiddleware, async (req, res) => {
  const courses = await Course.find();
  res.json(courses);
});

// --- ADD THIS NEW ROUTE ---
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

  app.patch('/api/courses/:id/publish', authMiddleware  , async (req, res) => {
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

app.patch('/api/courses/:id/unpublish', authMiddleware  , async (req, res) => {
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

// --- User Routes ---
//  NEW: Get all users (Admin only)
app.get('/api/users', authMiddleware, async (req, res) => {
  try {
    // .select('-password') prevents the hashed password from being sent to the frontend
    const users = await User.find().select('-password');
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
