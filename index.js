import express from "express";
import bodyParser from "body-parser";
import pg from "pg";
import bcrypt from "bcrypt";
import passport from "passport";
import { Strategy } from "passport-local";
import GoogleStrategy from "passport-google-oauth2";
import session from "express-session";
import env from "dotenv";

env.config();
const app = express();
const port = 3000;
const saltRounds = 10;

app.use(
  session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: true,
  })
);
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static("public"));
app.use(passport.initialize());
app.use(passport.session());
app.set("view engine", "ejs");

const db = new pg.Client({
  user: process.env.PG_USER,
  host: process.env.PG_HOST,
  database: process.env.PG_DATABASE,
  password: process.env.PG_PASSWORD,
  port: process.env.PG_PORT,
});
db.connect();

app.get("/", (req, res) => {
  res.render("home", { user: req.user });
});
app.get("/login", (req, res) => {
  res.render("login", { user: req.user, error: null });
});
app.get("/register", (req, res) => {
  res.render("register", { user: req.user, error: null });
});
app.get("/logout", (req, res, next) => {
  req.logout(err => { if (err) return next(err); res.redirect("/"); });
});
app.get("/whispers", async (req, res) => {
  if (req.isAuthenticated()) {
    try {
      const result = await db.query("SELECT secret FROM users WHERE email = $1 AND secret IS NOT NULL", [req.user.email]);
      res.render("whispers", { user: req.user, whispers: result.rows });
    } catch (err) {
      console.error(err);
      res.status(500).send("Server error");
    }
  } else {
    res.redirect("/login");
  }
});
app.get("/submit", (req, res) => {
  if (req.isAuthenticated()) res.render("submit", { user: req.user });
  else res.redirect("/login");
});
app.post("/submit", async (req, res) => {
  try {
    await db.query("UPDATE users SET secret = $1 WHERE email = $2", [req.body.secret, req.user.email]);
    res.redirect("/whispers");
  } catch (err) {
    console.error(err);
    res.status(500).send("Server error");
  }
});
app.post("/login", passport.authenticate("local", { successRedirect: "/whispers", failureRedirect: "/login" }));
app.post("/register", async (req, res) => {
  const email = req.body.username;
  const password = req.body.password;
  try {
    const checkResult = await db.query("SELECT * FROM users WHERE email = $1", [email]);
    if (checkResult.rows.length > 0) {
      return res.render("register", { user: req.user, error: "Email already registered. Please login." });
    }
    const hash = await bcrypt.hash(password, saltRounds);
    const result = await db.query("INSERT INTO users (email, password) VALUES ($1, $2) RETURNING *", [email, hash]);
    req.login(result.rows[0], err => {
      if (err) {
        console.error(err);
        return res.render("register", { user: req.user, error: "Registration error. Please try again." });
      }
      res.redirect("/whispers");
    });
  } catch (err) {
    console.error(err);
    res.status(500).send("Server error");
  }
});
passport.use(
  "local",
  new Strategy(async function verify(username, password, cb) {
    try {
      const result = await db.query("SELECT * FROM users WHERE email = $1", [username]);
      if (result.rows.length > 0) {
        bcrypt.compare(password, result.rows[0].password, (err, valid) => {
          if (err) return cb(err);
          return cb(null, valid ? result.rows[0] : false);
        });
      } else return cb(null, false);
    } catch (err) {
      return cb(err);
    }
  })
);
passport.use(
  "google",
  new GoogleStrategy(
    {
      clientID: process.env.GOOGLE_CLIENT_ID,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET,
      callbackURL: "http://localhost:3000/auth/google/whispers",
      userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo",
    },
    async (accessToken, refreshToken, profile, cb) => {
      try {
        const result = await db.query("SELECT * FROM users WHERE email = $1", [profile.email]);
        if (result.rows.length === 0) {
          const newUser = await db.query("INSERT INTO users (email, password) VALUES ($1, $2) RETURNING *", [profile.email, "google"]);
          return cb(null, newUser.rows[0]);
        } else return cb(null, result.rows[0]);
      } catch (err) {
        return cb(err);
      }
    }
  )
);
passport.serializeUser((user, cb) => { cb(null, user); });
passport.deserializeUser((user, cb) => { cb(null, user); });
app.get("/auth/google", passport.authenticate("google", { scope: ["profile", "email"] }));
app.get("/auth/google/whispers", passport.authenticate("google", { successRedirect: "/whispers", failureRedirect: "/login" }));
app.listen(port, () => {
  console.log(`Server running on port ${port} - Designed by Saad Tiwana`);
});
