
const express = require("express");
const mongoose = require("mongoose");
const cors = require("cors");
const dotenv = require("dotenv");
const bcrypt = require("bcrypt");
const nodemailer = require('nodemailer');
const bodyParser = require('body-parser');
const crypto = require('crypto');  // To generate random OTPs
const jwt = require("jsonwebtoken");
const { Server } = require("socket.io");
const { type } = require("os");
const path = require('path');
const multer = require('multer');

dotenv.config();

const app = express();
app.use(express.json());
// Middleware to serve static files
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));
app.use(cors());
app.use(bodyParser.json());

const PORT = process.env.PORT || 7760;
const MONGO_URI = process.env.MONGO_URI;



// Connect to MongoDB
mongoose.connect(MONGO_URI, { useNewUrlParser: true, useUnifiedTopology: true })
    .then(() => console.log("MongoDB connected"))
    .catch((err) => console.error(err));

    app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
app.use(cors({
  origin: ['https://sign-frontend.vercel.app/', 'https://your-backend.onrender.com'],
  methods: ['GET', 'POST', 'DELETE', 'PUT'],
}));


    // To Store Uploads
    const upload = multer({
        storage: multer.diskStorage({
            destination: (req, file, cb) => {
                cb(null, 'uploads/');
            },
            filename: (req, file, cb) => {
                cb(null, Date.now() + path.extname(file.originalname));
            }
        }),
        fileFilter: (req, file, cb) => {
            const filetypes = /jpeg|jpg|png|gif|bmp|webp|tiff|svg|mp4|mov|avi|mkv|flv|wmv|webm|mpg|mpeg|3gp/;  // All common image and video formats
            const mimetype = filetypes.test(file.mimetype);
            const extname = filetypes.test(path.extname(file.originalname).toLowerCase());
    
            if (mimetype && extname) {
                return cb(null, true);
            }
            cb(new Error('Invalid file type. Only images and videos are allowed.'));
        }
    });

// User Schema
const userSchema = new mongoose.Schema({
    username: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    email:{type:String,required:true,unique: true},
    phoneNumber:{type:String}
});

const User = mongoose.model("User", userSchema);


// Setup Nodemailer Transporter
const transporter = nodemailer.createTransport({
    service: 'gmail', // You can change this to another email service (e.g., Outlook, Yahoo)
    auth: {
        user: process.env.EMAIL_USER, // Replace with your email
        pass: process.env.EMAIL_PASS,   // Replace with your email password or app-specific password
    },
});

// Route to send OTP
app.post('/send-otp', (req, res) => {
    const { email } = req.body; // Get email from client
    if (!email) {
        return res.status(400).send('Email is required');
    }

    // Generate a random 6-digit OTP
    const otp = crypto.randomInt(100000, 999999);

    // Send OTP via email
    const mailOptions = {
        from: 'cheluvaraj1011@gmail.com',  // Replace with your email
        to: email,
        subject: 'Your OTP Code',
        text: `Your OTP code is ${otp}`,
    };

    transporter.sendMail(mailOptions, (error, info) => {
        if (error) {
            console.log(error);
            return res.status(500).send('Error sending OTP');
        } else {
            console.log('OTP sent: ' + info.response);
            return res.status(200).send({ otp, message: 'OTP sent successfully' });  // Send OTP back to verify
        }
    });
});

app.post('/verify-otp', (req, res) => {
    const { enteredOtp, generatedOtp } = req.body;
  
    console.log('Received OTP:', req.body); // Log the entire request body
    if (String(enteredOtp) === String(generatedOtp)) {
      return res.status(200).send('OTP verified successfully');
    } else {
      return res.status(400).send('Invalid OTP');
    }
  });

  // POST API to create a new user
app.post('/Newuser', async (req, res) => {
    const { username, password, email, phoneNumber } = req.body;
  console.log(req.body)
    // Validate required fields
    if (!username || !password || !email) {
      return res.status(400).json({ message: 'Username, password, and email are required.' });
    }
  
    try {
      // Check if the user already exists
      const existingUser = await User.findOne({ $or: [{ username }, { email }] });
      if (existingUser) {
        return res.status(400).json({ message: 'User with this username or email already exists.' });
      }
  
      // Hash password before saving
      const hashedPassword = await bcrypt.hash(password, 10);
  
      // Create a new user
      const newUser = new User({
        username,
        password: hashedPassword,
        email,
        phoneNumber,
      });
  
      // Save the user to the database
      await newUser.save();
  
      // Send response
      res.status(201).json({ message: 'User created successfully!', user: newUser });
    } catch (error) {
      console.error(error);
      res.status(500).json({ message: 'Server error, please try again later.' });
    }
  });

// Login in to the Account

app.post("/login", async (req, res) => {
  console.log(req.body);

  // Fetch user data based on the email provided
  let fetchedData = await User.find({ email: req.body.email });
  console.log(fetchedData);

  // Check if the user exists
  if (fetchedData.length > 0) {
      // Compare the provided password with the stored hashed password
      const isPasswordValid = await bcrypt.compare(req.body.password, fetchedData[0].password);

      if (isPasswordValid) {
          // Password is correct, proceed with successful login
          let dataToSend = {
              // Add any data you want to send back here, like user information, token, etc.
              userId: fetchedData[0]._id,
              email: fetchedData[0].email,
              phoneNumber:fetchedData[0].phoneNumber,
              name:fetchedData[0].username,
              // You could also send a JWT token if you're using authentication tokens
          };
          res.json({ status: "Success", msg: "Login Successfully ✅", data: dataToSend });
      } else {
          // Invalid password
          res.json({ status: "Failed", msg: "Invalid Password ❌" });
      }
  } else {
      // User not found
      res.json({ status: "Failed", msg: "User Does Not Exist ❌" });
  }
});

let ItemsSchema = {
    text:{
        type:String,
        required:true
    },
    category:{
        type:String,
        required:true
    },
    file:{
        type:String,
        required:true
    }
}

let Item = mongoose.model("Item",ItemsSchema);

app.post("/NewItem",upload.array("file"),async(req,res)=>{

    let ItemArr=await Item.find().and({text:req.body.text});
    if (ItemArr.length>0) {
        res.json({status:"failure",msg:"Text already Exist❌"});
    }else{
    try{
        let newItem = new Item({          
            
            file:req.files[0].path,
            text:req.body.text,
            category:req.body.category,
            

        });
        await newItem.save();
        res.json({status:"Success",msg:" Item Added Successfully✅"});
    }catch(error){
        res.json({status:"Failed",error:error,msg:"Invalid Details ❌"});
        console.log(error)
    }
    }
}
);

app.get('/ItemData/:category', async (req, res) => {
    const category = req.params.category;
    const searchText = req.query.search || ''; // Get search text from query parameters
  
    try {
      // Build the query object dynamically
      const query = {
        ...(category !== 'All' && { category }), // Include category filter only if it's not "all"
        text: { $regex: searchText, $options: 'i' }, // Case-insensitive search
      };
  
      const items = await Item.find(query);
  
      if (items.length === 0) {
        return res.status(404).json({ message: "No items found for this category and search text" });
      }
  
      res.status(200).json({ items });
    } catch (error) {
      console.error(error);
      res.status(500).json({ message: "Server Error", error });
    }
  });
  
  app.get('/ItemDataByCategory/:category', async (req, res) => {
    const category = req.params.category;
  
    try {
      // If the category is "all", fetch all items; otherwise, filter by category
      const query = category !== 'all' ? { category } : {};
  
      const items = await Item.find(query);
  
      if (items.length === 0) {
        return res.status(404).json({ message: "No items found for this category" });
      }
  
      res.status(200).json({ items });
    } catch (error) {
      console.error(error);
      res.status(500).json({ message: "Server Error", error });
    }
  });

// API to delete an item by ID
app.delete('/items/:id', async (req, res) => {
  const { id } = req.params;

  try {
      const deletedItem = await Item.findByIdAndDelete(id);

      if (!deletedItem) {
          return res.status(404).json({ status: "Fail", message: "Item not found" });
      }

      res.status(200).json({ status: "Success", message: "Item deleted successfully", data: deletedItem });
  } catch (error) {
      console.error("Error deleting item:", error);
      res.status(500).json({ status: "Fail", message: "Server error" });
  }
});

app.put('/update-password', async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ message: 'Email and password are required.' });
  }

  try {
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(404).json({ message: 'User not found.' });
    }

      // Hash password before saving
      const hashedPassword = await bcrypt.hash(password, 10);

    user.password = hashedPassword; // Hash the password in production
    await user.save();

    res.status(200).json({ message: 'Password updated successfully ✅' });
  } catch (error) {
    res.status(500).json({ message: 'Error updating password.' });
  }
});
  
