const express = require("express");
const http = require("http");
const mongoose = require("mongoose");
const dotenv = require("dotenv");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const cookieparser = require("cookie-parser");
const cors = require("cors");
const User = require("./models/User");
const app = express();
const server = http.createServer(app);


app.use(express.json());  // for accessing req.body from forms.
app.use(cookieparser()); //Used for extracting the cookies
dotenv.config();
const PORT = process.env.PORT || 80;

// Database Connection
mongoose.connect(process.env.Mongourl,
    { useNewUrlParser: true, useUnifiedTopology: true },
    () => {
        console.log("Connected to db");
    });



// ROUTES

cors: {
    origin: ["http://localhost:3000","https://inspiring-shockley-9cb7b6.netlify.app/"]
}



app.all('*', function(req, res, next) {
            let origin = req.headers.origin;
            res.header("Access-Control-Allow-Origin", origin);
            res.header("Access-Control-Allow-Credentials", true);
                     
            res.header("Access-Control-Allow-Headers", "Origin, X-Requested-With, Content-Type, Accept");
            next();
        });


app.get("/", (req, res)=>{
    res.send("server up and running");
});
app.get("/user", auth, (req, res) => {
    let token = "";
    token = req.cookies.savedtoken;
    console.log("Allowed login attempt");
    if(!token) res.status(400).json({err: "Token not found"});
    else res.status(200).json({err: null});
});


app.post("/register", async (req, res) => {
    const { name, email, password, password2 } = req.body;
    console.log(req.body);

    // checking the passwords are same
    if (password === password2) {
        // hashing the password
        const salt = await bcrypt.genSalt(10);
        const hashedpass = await bcrypt.hash(password, salt);

        // Checking if existing User
        const existinguser = await User.findOne({ email: email });
        if (existinguser) res.status(400).json({error: "User Already Exists!", email: null, added: false});
        else {
            const user = new User({
                name: name,
                email: email,
                password: hashedpass
            });
            try {
                const savedUser = await user.save();
                res.status(200).json({error:null, email: savedUser.email, added: true});
            }
            catch (err) {
                res.status(400).json({error: err, email: null, added: false});
            }
        }
    }
    else {
        res.status(400).json({error: "Passwords do not match", email: null, added: false});
    }
});


app.post("/login", async (req, res) => {
    const { email, password } = req.body;

    // checking if the user exists
    const userexist = await User.findOne({ email: email });
    if (!userexist) res.status(200).json({error: "User Not Found!", loggedin: false});
    else {
        // validating the password
        const validpass = await bcrypt.compare(password, userexist.password);
        if (validpass) {
            // creating the json web token for the current user
            const token = jwt.sign({ email }, process.env.tokenSecret);

            res.cookie("savedtoken", token, {
                maxAge: 60 * 1000 * 60,
                httpOnly: true,
                sameSite: 'none',
                secure: true
            });
            res.status(200).json({error: null, loggedin: true});
        }
        else res.status(200).json({error: "Incorrect password", loggedin: false});
    }

});

// FUNCTION FOR AUTHENTICATION
function auth(req, res, next) {
    const token = req.cookies.savedtoken;
    if (!token) res.status(400).send("Token not found");
    else {
        try {
            // verification of the token
            const ver_token = jwt.verify(token, process.env.tokenSecret);
            next();
        }
        catch{
            res.status(401).send("Invalid token found");
        }


    }
}

// Listening to port
server.listen(PORT, () => {
    console.log("server up and runnin'");
});