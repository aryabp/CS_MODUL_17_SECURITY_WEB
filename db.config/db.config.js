const { Client } = require('pg');
require('dotenv').config()

const { 
    DB_HOST_DEV,
    DB_USER_DEV,
    DB_PASS_DEV,
    DB_NAME_DEV,
    DB_PORT_DEV
} = process.env;

const db = new Client({
    user: DB_USER_DEV,
    host: DB_HOST_DEV,
    database: DB_NAME_DEV,
    password: DB_PASS_DEV,
    port: DB_PORT_DEV
});

module.exports = db;