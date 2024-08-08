import dotenv from "dotenv";
dotenv.config();
import bcrypt from "bcrypt";
import express from "express";
import bodyParser from "body-parser";
import pg from "pg";
import jwt from "jsonwebtoken";
import cookieParser from "cookie-parser";
import session from "express-session";

const jwtSecret = process.env.JWT_SECRET;

/**
 * Creating connection to PostgreSQL database
 */
const db = new pg.Client({
  user: "postgres",
  host: "localhost",
  database: "userLogs",
  password: "goodluck",
  port: 5432,
});

/**
 * Connecting database
 */
try {
  db.connect();
  console.log("Database connected!");
} catch (error) {
  console.log(error);
}

//Create an server app
const app = express();
const PORT = 3000;

//Middlewares
app.use(express.urlencoded({ extended: true }));
app.use(express.static("public"));
app.use(express.json());
app.use(cookieParser());
app.use(
  session({
    secret: "keyboard cat",
    resave: false,
    saveUninitialized: true,
  })
);

/**
 * Creating an authentication middleware to get user securely loged in.
 * This middleware uses token which comes from "/checkLogin" route.
 */
const authMiddleware = (req, res, next) => {
  const token = req.cookies.token;
  console.log(token);

  if (!token) {
    return res.status(401).json({ message: "Unauthorized" });
  }

  try {
    //verify token and secret(given by developer) using jwt.verify() method.
    const decoded = jwt.verify(token, jwtSecret);
    req.userId = decoded.userId;
    next();
  } catch (error) {
    return res.status(401).json({ message: "Unauthorized" });
    console.log(error);
  }
};

/**
 * GET Home Page
 */
app.get("/", async (req, res) => {
  try {
    const locals = {
      title: "User Registration",
      description: "User Registration System",
    };
    res.render("index.ejs", { locals });
  } catch (error) {
    console.log(error);
  }
});

/**
 * Registration of user
 * Post data to the server and inert user data into database.
 * Hashing of password or password encryption
 */
app.post("/submit", async (req, res) => {
  const name = req.body.name;
  const email = req.body.email;
  const password = req.body.password;
  const confirm_password = req.body.confirm_password;

  //Hashing of password
  const hashedPassword = await bcrypt.hash(password, 4);
  console.log(hashedPassword);

  //Check email format using Regex
  let pattern = /^[^\s@]+@[^\s@]+\.\w*/g;

  try {
    //If email is in correct format and both passwords are matched, then insert data into database.
    if (pattern.test(email) && password === confirm_password) {
      db.query(
        "INSERT INTO user_data (name, email, password) VALUES ($1, $2, $3)",
        [name, email, hashedPassword]
      );
      // res.send("Registered successfuly!");
      res.render("navigation.ejs", {
        title: "Registered successfully!",
        description: "UMS",
        message: "You are registered successfuly!",
      });
    } else {
      res.render("navigation.ejs", {
        title: "Registration Failed!",
        description: "UMS",
        message: "Something went wrong, please try again!",
      });
    }
  } catch (error) {
    console.log(error);
    res.send(error);
  }
});

/**
 * Login Page
 * Render Login Page when user click on login now link in index.ejs
 */
app.get("/login", async (req, res) => {
  try {
    const locals = {
      title: "User Login",
      description: "Login Page",
    };
    res.render("login.ejs", { locals });
  } catch (error) {
    console.log(error);
  }
});

/**
 * Check user login credentials against the database's data and render dashboard page
 */
app.post("/checkLogin", async (req, res) => {
  const email = req.body.email;
  const password = req.body.password;
  // console.log(email, password);
  try {
    const result = await db.query("SELECT * FROM user_data WHERE email = $1", [
      email,
    ]);
    const dbId = result.rows[0].id;
    const dbEmail = result.rows[0].email;
    const dbPassword = result.rows[0].password;

    const user = dbId;

    //Check hashed password and user enterd password to get user loged in
    const isPasswordValid = await bcrypt.compare(password, dbPassword);

    //Creating token with jwt sign method and assigning an secret to it for authentication.
    if (isPasswordValid) {
      const token = jwt.sign({ userId: user }, jwtSecret);
      res.cookie("token", token, { httpOnly: true });

      res.render("dashboard.ejs", {
        title: "Dasboard",
        description: "UMS",
      });
    } else {
      res.render("navigation.ejs", {
        title: "Error",
        description: "UMS",
        message: "Invalid credentials, Try again!",
      });
    }
  } catch (error) {
    console.log(error);
  }
});

/**
 * Rendering dashboard page and secure it using session, cookies and token
 */
app.get("/afterlogin", authMiddleware, async (req, res) => {
  try {
    const locals = {
      title: "Dashboard",
      description: "UMS",
    };
    res.render("dashboard.ejs", { locals });
  } catch (error) {
    console.log(error);
  }
});

/**
 * Get Delete account page
 */
app.get("/delete", async (req, res) => {
  try {
    const locals = {
      title: "Delete Account Page",
      description: "UMS",
    };
    res.render("deleteAcc.ejs", { locals });
  } catch (error) {
    console.log(error);
  }
});

/**
 * Delete Account or delete individual user data
 */
app.post("/deleteAccount", async (req, res) => {
  try {
    const email = req.body.email;
    const password = req.body.password;
    console.log(email);

    // res.redirect("/");

    await db.query("DELETE FROM user_data WHERE email=$1", [email]);

    res.render("navigation.ejs", {
      title: "Account Deleted!",
      description: "UMS",
      message: "You account has been deleted successfuly!",
    });
  } catch (error) {
    console.log(error);
  }
});

/**
 * Logout user from the dashboard page
 */
app.get("/logout", (req, res) => {
  res.clearCookie("token");
  // res.redirect("/");
  res.render("navigation.ejs", {
    title: "User logedout!",
    description: "UMS",
    message: "You are logged out successfuly!",
  });
});

app.listen(process.env.PORT || PORT, () => {
  console.log(`App started on ${PORT}`);
});
