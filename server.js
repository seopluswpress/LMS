import express from 'express';
import mongoose from 'mongoose';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import cors from 'cors';
import dotenv from 'dotenv';

dotenv.config();
const app = express();
app.use(express.json());
// Define the allowed origins for CORS
const allowedOrigins = [
  'http://localhost:3000', // Your local frontend
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
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  credentials: true,
}));

// ======================
// MongoDB Models
// ======================

const userSchema = new mongoose.Schema({
  username: String,
  email: String,
  password: String,
  role:String,
  courses: [{ type: mongoose.Schema.Types.ObjectId, ref: 'Course' }],
});

const sectionSchema = new mongoose.Schema({
  title: { type: String, required: true },
  youtubeUrl: { type: String, required: true },
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

// Register user
app.post('/api/register', async (req, res) => {
  try {
    const { username, email, password, role } = req.body;

    // Check if user already exists
    const existingUser = await User.findOne({ email });
    if (existingUser) return res.status(400).json({ message: 'User already exists' });

    // Hash password
    const hashed = await bcrypt.hash(password, 10);

    // Create user with role (default to 'user')
    const user = await User.create({
      username,
      email,
      password: hashed,
      role: role || 'user',
    });

    // Generate JWT including id and role
    const token = jwt.sign(
      { id: user._id, role: user.role },
      process.env.JWT_SECRET,
      { expiresIn: '1h' }
    );

    // Send token and user info to frontend
    res.json({
      message: 'User created',
      token,
      user: { id: user._id, username: user.username, email: user.email, role: user.role },
    });

  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Internal server error' });
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
app.post('/api/courses', authMiddleware, async (req, res) => {
  const { title, youtubeUrl, description } = req.body;
  const course = await Course.create({ title, youtubeUrl, description });
  res.json(course);
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

// ======================
// Connect MongoDB & Start
// ======================

mongoose.connect(process.env.MONGO_URI)
  .then(() => {
    console.log('MongoDB connected');
    app.listen(process.env.PORT, () => console.log(`Server running on ${process.env.PORT}`));
  })
  .catch(err => console.log(err));
