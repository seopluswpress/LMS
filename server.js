import express from 'express';
import mongoose from 'mongoose';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import cors from 'cors';
import dotenv from 'dotenv';
import nodemailer from 'nodemailer';

dotenv.config();
const app = express();
app.use(express.json());
// Define the allowed origins for CORS
const allowedOrigins = [
  'http://localhost:3000', // Your local frontend
  'https://your-deployed-frontend-url.com', // IMPORTANT: Replace with your actual frontend URL when you deploy it
  'http://localhost:5173',
  'https://smbjugaad.com'
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
  role:String,
  courses: [{ type: mongoose.Schema.Types.ObjectId, ref: 'Course' }],
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



// Register user


app.post('/api/register', async (req, res) => {
  try {
    const { username, email, password, role } = req.body;
    console.log('📩 Incoming registration:', { username, email, role });

    // Step 1: Check if user exists
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      console.log('⚠️ User already exists:', email);
      return res.status(400).json({ message: 'User already exists' });
    }

    // Step 2: Hash password
    const hashed = await bcrypt.hash(password, 10);

    // Step 3: Create user
    const user = await User.create({
      username: username || email.split('@')[0],
      email,
      password: hashed,
      role: role || 'user',
    });
    console.log('✅ User created in MongoDB:', user.email);

    // Step 4: Generate token
    const token = jwt.sign(
      { id: user._id, role: user.role },
      process.env.JWT_SECRET,
      { expiresIn: '1h' }
    );

    // Step 5: Email configuration debug
    console.log('📧 Preparing email using Gmail transporter...');
    console.log('ENV Email user:', process.env.EMAIL_USER);
    console.log('ENV Frontend URL:', process.env.FRONTEND_URL);

    const transporter = nodemailer.createTransport({
      service: 'gmail',
      auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS,
      },
    });

    // Verify the transporter before sending
    await transporter.verify()
      .then(() => console.log('✅ Email transporter verified successfully'))
      .catch(err => {
        console.error('❌ Transporter verification failed:', err);
        throw new Error('Email transporter verification failed');
      });

    const loginUrl = `${process.env.FRONTEND_URL}/login?email=${encodeURIComponent(email)}`;
    console.log('🔗 Generated Login URL:', loginUrl);

    const mailOptions = {
      from: `"SMBJugaad LMS" <${process.env.EMAIL_USER}>`,
      to: email,
      subject: 'Welcome to SMBJugaad LMS 🎉',
      html: `
        <div style="font-family: Arial, sans-serif; color: #333;">
          <h2>Welcome to SMBJugaad LMS, ${user.username}!</h2>
          <p>We’re excited to have you on board.</p>
          <p>You can now log in to start exploring your courses:</p>
          <a href="${loginUrl}"
             style="display:inline-block;background:#4f46e5;color:white;text-decoration:none;
                    padding:10px 20px;border-radius:6px;font-weight:600;">
             Log in to SMBJugaad
          </a>
          <p>If the button doesn’t work, copy and paste this link in your browser:</p>
          <p style="color:#555;">${loginUrl}</p>
          <hr/>
          <p style="font-size:12px;color:#999;">© ${new Date().getFullYear()} SMBJugaad LMS</p>
        </div>
      `,
    };

    console.log('📤 Sending email to:', email);

    // Step 6: Send email
    await transporter.sendMail(mailOptions);
    console.log(`✅ Registration email sent successfully to ${email}`);

    // Step 7: Respond success
    res.json({
      message: 'User registered successfully and email sent',
      token,
      user: { id: user._id, username: user.username, email: user.email, role: user.role },
    });

  } catch (error) {
    console.error('💥 Error during registration:', error);
    res.status(500).json({ message: 'Internal server error', error: error.message });
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
