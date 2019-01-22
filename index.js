const express = require('express');
const bodyParser = require('body-parser');
const mysql = require('mysql');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cors = require('cors');

const secret = "ververver";
const app = express();

app.use(bodyParser());
app.use(cors());

const pool = mysql.createPool({
    host: 'localhost',
    user: 'root',
    password: '',
    database: 'db_checker'
});

app.post('/login', hasUsernamePass, (req, res) => {
    let sql = "SELECT * FROM user WHERE username = ? ";
    pool.query(sql, [req.body.username], (err,result)=>{
        if(err) return handleError();
        if(result.length == 1){
            if(bcrypt.compareSync(req.body.password, result[0].password)){
                const user = result[0];
                const payload = {
                    user_id: user.user_id,
                    username: user.username,
                    is_admin: user.is_admin
                };
                const token = jwt.sign(payload,secret);
                res.json({token});
            }
        } else{
            res .status(400)
                .json({message: "Invalid email/password"})
        }
    });
});

app.post('/signup', hasUsernamePass, (req, res) => {
    req.body.password = bcrypt.hashSync(req.body.password, 10);
    let sql = "INSERT INTO user SET ?";
    pool.query(sql, req.body, (err,result) => {
        if(err) return handleError(err, res);
        res .status(201)
            .json({message: "Success!"});
    });
});

function hasUsernamePass(req, res, next){
    if(!!req.body.username && !!req.body.password){
        next();
    } else {
        res .status(422)
            .json({message: "Username and password required"});
    }
}

function handleError(error, res){
    res .status(500)
        .json({error});
}

app.listen(8080, ()=>{
    console.clear();
    console.log("checker backend listening on port 8080");
});