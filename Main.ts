import express from "express";
import pg from "pg";
import jwt from "jsonwebtoken";
import bodyParser from "body-parser";
import bcrypt from "bcrypt";
import cors from "cors";

const app = express();
const port = 3001;

app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.json());
app.use(cors());

const db = new pg.Client({
  connectionString:
    "postgresql://josephiannuzzelli4561:f5LIBtRr7OQF@ep-billowing-morning-02647692.us-east-2.aws.neon.tech/Users?sslmode=require",
});

db.connect()
  .then((result) => {
    console.log("Connected to database!");
  })
  .catch((e) => {
    console.log(e);
  });

app.post("/api/auth/signup", async (req, res) => {
  try {
    type userSignUpDetails = {
      apitoken: string;
      username: string;
      password: string;
      email: string;
      fname: string;
      lname: string;
    };
    const user: userSignUpDetails = req.body;
    if (
      user.apitoken &&
      user.username &&
      user.password &&
      user.email &&
      user.fname &&
      user.lname
    ) {
      const checkAuthKey = await db.query(
        "SELECT * FROM apikeys WHERE apikeyid = $1",
        [user.apitoken]
      );
      if (checkAuthKey.rows.length < 1) {
        return res.status(406);
      }

      const checkEmail = await db.query(
        "SELECT * FROM users WHERE email = $1",
        [user.email]
      );
      const checkUsername = await db.query(
        "SELECT * FROM users WHERE username = $1",
        [user.username]
      );
      if (checkUsername.rows.length > 0 || checkEmail.rows.length > 0) {
        return res.status(401);
      }

      const hashedpassword = await bcrypt.hash(user.password, 10);
      const userObject = await db.query(
        "INSERT INTO users(username, password, email, fname, lname, apisession) VALUES($1, $2, $3, $4, $5, $6) RETURNING *",
        [
          user.username,
          hashedpassword,
          user.email,
          user.fname,
          user.lname,
          user.apitoken,
        ]
      );
      const userJWT = jwt.sign(userObject.rows[0], "ASDASDSADASDASDASDASD");
      return res.json({ userJWT: userJWT });
    } else {
      return res.status(404);
    }
  } catch (error) {
    console.error(error);
    return res.status(500);
  }
});

app.post("/api/auth/login", async (req, res) => {
  try {
    type userSignInDetails = {
      apitoken: string;
      username: string;
      password: string;
    };
    const user: userSignInDetails = req.body;
    if (user.apitoken && user.username && user.password) {
      const checkAuthKey = await db.query(
        "SELECT * FROM apikeys WHERE apikeyid = $1",
        [user.apitoken]
      );
      if (checkAuthKey.rows.length < 1) {
        return res.status(406);
      }

      let checkUsername = await db.query(
        "SELECT * FROM users WHERE username = $1",
        [user.username]
      );
      if (checkUsername.rows.length < 1) {
        const checkEmail = await db.query(
          "SELECT * FROM users WHERE email = $1",
          [user.username]
        );
        if (checkEmail.rows.length < 1) {
          return res.status(401);
        }
        checkUsername = checkEmail;
      }

      const isPassword = await bcrypt.compare(
        user.password,
        checkUsername.rows[0].password
      );
      if (!isPassword) {
        return res.status(401);
      } else {
        const userJWT = jwt.sign(
          checkUsername.rows[0],
          "ASDASDSADASDASDASDASD"
        );
        return res.json({ userJWT: userJWT });
      }
    } else {
      return res.status(404);
    }
  } catch (error) {
    console.error(error);
    return res.status(500);
  }
});

app.post("/api/auth/getuser", async (req, res) => {
  try {
    type getUserDetails = {
      userjwt: string;
      apitoken: string;
    };
    const user: getUserDetails = req.body;

    const checkAuthKey = await db.query(
      "SELECT * FROM apikeys WHERE apikeyid = $1",
      [user.apitoken]
    );
    if (checkAuthKey.rows.length < 1) {
      return res.status(401);
    }

    const userObject = jwt.verify(user.userjwt, "ASDASDSADASDASDASDASD");
    return res.json({ user: userObject });
  } catch (error) {
    console.error(error);
    return res.status(500);
  }
});

app.put("/api/auth/changeuser", async (req, res) => {
  try {
  } catch (error) {
    console.error(error);
    return res.status(500);
  }
});

app.listen(port);
