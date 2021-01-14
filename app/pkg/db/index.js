const mongoose = require('mongoose');
const cfg = require('../config');

let username = cfg.get('db').username;
let password = cfg.get('db').password;
let dbname = cfg.get('db').dbname;
let host = cfg.get('db').host;

let dsn = `mongodb+srv://${username}:${password}@${host}/${dbname}?retryWrites=true&w=majority`;

mongoose.connect(
    dsn,
    {
        useNewUrlParser: true,
        useUnifiedTopology: true
    },
    err => {
        if (err) {
            return console.log('Could not connect to database: ', err);
        }
        console.log('Successfully conneted to database');
    }
);