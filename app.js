const express = require("express")
const morgan = require("morgan")
const path = require("path")
const session = require("express-session")
const passport = require("passport")
const LocalStrategy = require("passport-local").Strategy
const mongoose = require("mongoose")
const Schema = mongoose.Schema
const bcrypt = require("bcryptjs")
const MongoStore = require("connect-mongo")(session)

require("dotenv").config()

const mongoDb = process.env.MONGO_URI

const connection = mongoose.createConnection(mongoDb, {
  useUnifiedTopology: true,
  useNewUrlParser: true,
})
const sessionStore = new MongoStore({
  mongooseConnection: connection,
  collection: "sessions",
})

const User = connection.model(
  "User",
  new Schema({
    username: { type: String, required: true },
    password: { type: String, required: true },
  })
)

passport.use(
  new LocalStrategy((username, password, done) => {
    User.findOne({ username: username }, (err, user) => {
      if (err) {
        return done(err)
      }
      if (!user) {
        return done(null, false, { msg: "Incorrect username" })
      }
      bcrypt.compare(password, user.password, (err, res) => {
        if (res) {
          return done(null, user)
        } else {
          return done(null, false, { msg: "Incorrect password" })
        }
      })
    })
  })
)

passport.serializeUser((user, done) => {
  done(null, user.id)
})

passport.deserializeUser((id, done) => {
  User.findById(id, (err, user) => {
    done(err, user)
  })
})

const app = express()
app.set("views", __dirname)
app.set("view engine", "ejs")

app.use(
  session({
    secret: process.env.EXPRESS_SESSIONS_SECRET,
    resave: false,
    saveUninitialized: true,
    store: sessionStore,
    cookie: { maxAge: 300000 },
  })
)
app.use(passport.initialize())
app.use(passport.session())
app.use(express.urlencoded({ extended: false }))
app.use((req, res, next) => {
  res.locals.currentUser = req.user
  next()
})

app.get("/", (req, res) => {
  res.render("index", { user: req.user })
})

app.get("/signup", (req, res) => {
  res.render("sign-up-form")
})

app.post("/signup", (req, res, next) => {
  bcrypt.hash(req.body.password, 10, (err, hashedPassword) => {
    if (err) {
      return next(err)
    }
    const user = new User({
      username: req.body.username,
      password: hashedPassword,
    }).save((err) => {
      if (err) {
        return next(err)
      }
      res.redirect("/")
    })
  })
})

app.post(
  "/log-in",
  passport.authenticate("local", {
    successRedirect: "/",
    failureRedirect: "/",
  })
)

app.get("/logout", (req, res) => {
  req.logout()
  res.redirect("/")
})

app.use(morgan("combined"))
app.listen(process.env.PORT || 3000, () =>
  console.log("app listening on port 3000!")
)
