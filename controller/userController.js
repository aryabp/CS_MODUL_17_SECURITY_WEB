const express = require('express')
const db = require('../db.config/db.config')
const jwt = require('jsonwebtoken');
const Auth = require('../middleware/auth')
const cookieParser = require('cookie-parser');
require("dotenv").config();
const bcrypt = require('bcrypt');
SECRET = process.env.SECRET


const register = async (req, res, next) => {
    // * 7. silahkan ubah password yang telah diterima menjadi dalam bentuk hashing
    const { username, email, password, } = req.body;
    try {
        const hash = await bcrypt.hash(password, 10)

        // 8. Silahkan coding agar pengguna bisa menyimpan semua data yang diinputkan ke dalam database

        await db.query(`insert into unhan_modul_17 values (DEFAULT, $1, $2, $3)`,
            [username, email, hash])
        res.send('Data has been upadated')
    } catch (err) {
        if (err.code == '23505') {
            res.send(err.detail)
        } else {
            res.send('Data tidak valid')
        }
    }
}

const login = async (req, res, next) => {

    // 9. komparasi antara password yang diinput oleh pengguna dan password yang ada didatabase
    const { email, password } = req.body;
    try {
        const data = await db.query(`SELECT * FROM unhan_modul_17 WHERE email = $1;`, [email]) //Verifying if the user exists in the database
        const user = data.rows;
        if (user.length === 0) {
            res.status(400).json({
                error: "User is not registered, Sign Up first",
            });
        }
        else {
            // 9. komparasi antara password yang diinput oleh pengguna dan password yang ada didatabase
            bcrypt.compare(password, user[0].password, (err, result) => { //Comparing the hashed password
                if (err) {
                    res.status(500).json({
                        error: "Server error",
                    });
                } else if (result === true) { //Checking if credentials match
                    // 10. Generate token menggunakan jwt sign
                    const token = jwt.sign(
                        {
                            id: user[0].id,
                            email: user[0].email,
                            username: user[0].username,
                            password: user[0].password
                        },
                        process.env.SECRET
                    );
                    //11. kembalikan nilai id, email, dan username
                    res.cookie("JWT", token, { httpOnly: true, sameSite: "strict" }).status(200).json({
                        id: user[0].id,
                        email: user[0].email,
                        username: user[0].username
                    });
                }
                else {
                    //Declaring the errors
                    if (result != true)
                        res.status(400).json({
                            error: "Enter correct password!",
                        });
                }
            })
        }
    } catch (err) {
        console.log(err);
        res.status(500).json({
            error: "Database error occurred while signing in!", //Database connection error
        });
    };







}

const logout = async (req, res, next) => {

    try {
        // 14. code untuk menghilangkan token dari cookies dan mengembalikan pesan "sudah keluar dari aplikasi"  
        return res.clearCookie('JWT').send('Logout Succesfull')
    } catch (err) {
        console.log(err.message);
        return res.status(500).send(err)
    }

}

const verify = async (req, res, next) => {
    try {
        // 13. membuat verify
        const{email}=req.body;
        const user = await db.query(`SELECT * FROM unhan_modul_17 where email=$1`,[email])
        return res.status(200).json({
            id:user.rows[0].id,
            username:user.rows[0].username,
            email:user.rows[0].email,
            password:user.rows[0].password
        })


    } catch (err) {
        console.log(err.message);
        return res.status(500).send(err)
    }
}

module.exports = {
    register,
    login,
    logout,
    verify
}