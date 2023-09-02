const dotenv = require("dotenv").config();
const express = require("express");
const mongoose = require("mongoose");
const bodyParser = require("body-parser");
const cors = require("cors");
const userRoute = require("./routes/userRoute");
const app = express();
const errorHAndler = require("./middleWare/errorMiddleware");
const cookieParser = require("cookie-parser")

//middlewares
app.use(express.json());
app.use(cookieParser())
app.use(express.urlencoded({ extended: false }));
app.use(bodyParser.json());
app.use(cors())

//ERRor Handler middleware
app.use(errorHAndler);

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log("listening to port 5000");
});

// route middleware
app.use("/api/users", userRoute);
//routes
app.get("/", (req, res) => {
  res.send("HOME  page");
});

//connect to db
mongoose
  .connect(process.env.MONGO_URI)
  .then(() => {
    console.log("connected to  db");
  })
  .catch((err) => console.log(err));
