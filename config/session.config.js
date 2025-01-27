const session = require("express-session");
const MongoStore = require("connect-mongo");
const mongoose = require("mongoose");

module.exports = app => {
    app.use(
        session({
            secret: process.env.SESS_SECRET,
            resave: true,
            saveUninitialized: false,
            cookie: {maxAge: 60000}, // 60 * 1000 ms === 1 min
            store: MongoStore.create({
                mongoUrl: process.env.MONGODB_URI || "mongodb://localhost/basicAuth",
                ttl: 60 * 60 * 24 // 60sec * 60min * 24h => 1 day
            }),
        })
    );
};