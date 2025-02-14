import express from "express";
import bodyParser from "body-parser";
import pg from "pg";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import session from "express-session";
import dotenv from "dotenv";

dotenv.config();

const db = new pg.Client({
  user: process.env.DATABASE_USER,
  host: process.env.DATABASE_HOST,
  database: process.env.DATABASE_NAME,
  password: process.env.DATABASE_PASSWORD,
  port: process.env.DATABASE_PORT,
});

db.connect();

const app = express();
const port = 3000;
const saltRounds = 10;

// Middlewares
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.json());
app.use(express.static("assets"));
app.use(
    session({
      secret: process.env.SESSION_SECRET,
      resave: false,
      saveUninitialized: true,
      cookie: { maxAge: 1000 * 60 * 60 }, // 1 hour
    })
);

// JWT Helper Function
const generateToken = (user) => {
  return jwt.sign(
      { id: user.id, name: user.name, email: user.email },
      process.env.JWT_SECRET,
      { expiresIn: "1h" }
  );
};

// Routes
app.get("/", (req, res) => {
  res.render("index.ejs");
});

app.get("/signin", (req, res) => {
  res.render("signin.ejs");
});

app.get("/signup", (req, res) => {
  res.render("signup.ejs");
});

app.get("/forgot", (req, res) => {
  res.render("forgot-password.ejs");
});

app.get("/privacy-policy", (req, res) => {
  res.render("privacy-policy.ejs");
});

app.get("/terms-policy", (req, res) => {
  res.render("terms-policy.ejs");
});

app.get("/contact", (req, res) => {
  res.render("contact.ejs");
});

app.get("/chat", (req, res) => {
  res.render("chat.ejs");
});

app.get("/team", (req, res) => {
  res.render("team.ejs");
});

app.get("/help", (req, res) => {
  res.render("help.ejs");
});

app.get("/profile-details", (req, res) => {
  res.render("profile-details.ejs");
});

app.get("/dashboard", async (req, res) => {
  if (req.session.user) {
    try {
      // Fetch the user's details from the database
      const result = await db.query("SELECT id, name, email FROM users WHERE id = $1", [req.session.user.id]);
      if (result.rows.length > 0) {
        const userDetails = result.rows[0]; // Latest user details
        res.render("dashboard.ejs", { userDetails }); // Pass userDetails to the template
      } else {
        res.redirect("/signin"); // Redirect if user no longer exists
      }
    } catch (error) {
      console.error("Error fetching user details:", error);
      res.redirect("/signin");
    }
  } else {
    res.redirect("/signin");
  }
});

// Forgot Password Route
app.post("/forgotpassword", async (req, res) => {
  try {
    const { email, password } = req.body;
    const checkResult = await db.query("SELECT * FROM users WHERE email = $1", [email]);

    if (checkResult.rows.length === 0) {
      return res.send(`
        <script>
          alert("Email not found. Please sign up first.");
          window.location.href = "/forgot";
        </script>
      `);
    }

    const hash = await bcrypt.hash(password, saltRounds);
    await db.query("UPDATE users SET password = $1 WHERE email = $2", [hash, email]);

    res.send(`
      <script>
        alert("Password updated successfully. Please log in.");
        window.location.href = "/signin";
      </script>
    `);
  } catch (error) {
    console.error(error);
    res.send(`
      <script>
        alert("Server error. Please try again later.");
        window.location.href = "/forgot";
      </script>
    `);
  }
});

// Newsletter Subscription Route
app.post("/newsletter", async (req, res) => {
  try {
    const { email } = req.body;

    if (!email) {
      return res.send(`
        <script>
          alert("Please provide a valid email.");
          window.location.href = "/";
        </script>
      `);
    }

    await db.query("INSERT INTO newsletter (email) VALUES ($1)", [email]);

    res.send(`
      <script>
        alert("Thanks for subscribing!");
        window.location.href = "/";
      </script>
    `);
  } catch (error) {
    console.error(error);
    res.send(`
      <script>
        alert("Failed to subscribe. Please try again later.");
        window.location.href = "/";
      </script>
    `);
  }
});

// Signup Route
app.post("/signup", async (req, res) => {
  try {
    const { name, email, password } = req.body;
    const checkResult = await db.query("SELECT * FROM users WHERE email = $1", [email]);

    if (checkResult.rows.length > 0) {
      return res.send(`
        <script>
          alert("Email already exists, try logging in.");
          window.location.href = "/signup";
        </script>
      `);
    }

    const hash = await bcrypt.hash(password, saltRounds);
    const result = await db.query(
        "INSERT INTO users (name, email, password) VALUES ($1, $2, $3) RETURNING *",
        [name, email, hash]
    );

    const user = result.rows[0];
    req.session.user = user; // Save session
    res.send(`
      <script>
        alert("Registration successful!");
        window.location.href = "/dashboard";
      </script>
    `);
  } catch (error) {
    console.error(error);
    res.send(`
      <script>
        alert("Server error during registration.");
        window.location.href = "/signup";
      </script>
    `);
  }
});

// Signin Route
app.post("/signin", async (req, res) => {
  try {
    const { email, password } = req.body;
    const result = await db.query("SELECT * FROM users WHERE email = $1", [email]);

    if (result.rows.length === 0) {
      return res.send(`
        <script>
          alert("Invalid email or password.");
          window.location.href = "/signin";
        </script>
      `);
    }

    const user = result.rows[0];
    const match = await bcrypt.compare(password, user.password);

    if (match) {
      req.session.user = user; // Save session
      res.send(`
        <script>
          alert("Login successful!");
          window.location.href = "/dashboard";
        </script>
      `);
    } else {
      res.send(`
        <script>
          alert("Invalid email or password.");
          window.location.href = "/signin";
        </script>
      `);
    }
  } catch (error) {
    console.error(error);
    res.send(`
      <script>
        alert("Server error during login.");
        window.location.href = "/signin";
      </script>
    `);
  }
});

// Logout Route
app.post("/logout", (req, res) => {
  req.session.destroy(() => {
    res.send(`
      <script>
        alert("You have been logged out.");
        window.location.href = "/signin";
      </script>
    `);
  });
});

// Contact Route
app.post("/contact", async (req, res) => {
  const { contactName, contactPhone, contactEmail, subject, contactMessage } = req.body;

  if (!contactName || !contactPhone || !contactEmail || !subject || !contactMessage) {
    return res.status(400).send(`
      <script>
        alert("All fields are required.");
        window.location.href = "/contact";
      </script>
    `);
  }

  try {
    await db.query(
        `INSERT INTO faq (name, phone, email, subject, message)
       VALUES ($1, $2, $3, $4, $5)`,
        [contactName, contactPhone, contactEmail, subject, contactMessage]
    );
    res.send(`
      <script>
        alert("Your message has been sent successfully!");
        window.location.href = "/contact";
      </script>
    `);
  } catch (error) {
    console.error("Error saving contact form data:", error);
    res.status(500).send(`
      <script>
        alert("Failed to send your message. Please try again later.");
        window.location.href = "/contact";
      </script>
    `);
  }
});

app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});
