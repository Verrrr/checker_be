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
            } else {
                res .status(400)
                    .json({message: "Invalid email/password"})
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

app.post('/problems', [verifyToken, verifyAdmin], (req, res) => {
    const sql = "INSERT INTO problem SET ?";
    pool.query(sql, req.body, (err,result) => {
        if(err) return handleError(err, res);
        res .status(201)
            .json({
                problem_id: result.insertId,
                title: req.body.title,
                explanation: ""
            });
    });
});

app.patch('/problems/:id', [verifyToken, verifyAdmin], (req, res) => {
    const sql = "UPDATE problem SET ? WHERE problem_id = ?";
    pool.query(sql, [req.body, req.params.id], (err,result) => {
        if(err) return handleError(err, res);
        res.json({message: "Success!"});
    });
});

app.get('/problems', [verifyToken], (req, res) => {
    const sql = "SELECT * FROM problem";
    pool.query(sql, (err,result) => {
        if(err) return handleError(err, res);
        res.json(result);
    });
});

app.delete('/problems/:id', [verifyToken, verifyAdmin], (req, res) => {
    const sql = "DELETE FROM problem WHERE problem_id = ?";
    pool.query(sql, [req.params.id], (err,result) => {
        if(err) return handleError(err, res);
        res.status(200).json({message: "deleted"});
    });
});

app.get('/problems/:id/samples', [verifyToken, verifyAdmin], (req, res) => {
    const sql = "SELECT * FROM sample_case WHERE problem_id = ?";
    pool.query(sql, [req.params.id], (err,result) => {
        if(err) return handleError(err, res);
        res.json(result);
    });
});

app.post('/samples', [verifyToken, verifyAdmin], (req, res) => {
    const sql = "INSERT INTO sample_case SET ? ";
    pool.query(sql, req.body, (err,result) => {
        if(err) return handleError(err, res);
        let sampleCase = {
            sample_case_id: result.insertId,
            input: "",
            output: "",
            problem_id: 0
        };
        Object.assign(sampleCase, req.body);
        res.status(201).json(sampleCase);
    });
})

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

function verifyAdmin(req, res, next){
    if(!!req.token.is_admin) next();
    else 
        res .status(401)
            .json({message: "You are not allowed to make this action!"});
    
}

function verifyToken(req,res,next){
    res.setHeader('Content-type','Application/json');
    const bearerHeader = req.headers['authorization'];
    if(!!bearerHeader){
        if(bearerHeader.split(' ').length <= 1){
            //Checks if format Bearer 'token' is correct
            res.status(422).json({message: 'Invalid bearer fromat'});
        } else {
            const bearerToken = bearerHeader.split(' ')[1];
            jwt.verify(bearerToken,secret , (err,result) =>{
                if(err){
                    res.status(403).json({message: err.message});
                } else {
                    req.token = result;
                    next();
                }
            });
        }
    } else {
        res.status(403).json({message: "Token missing from header"});
    }
}

app.listen(8080, ()=>{
    console.clear();
    console.log("checker backend listening on port 8080");
});