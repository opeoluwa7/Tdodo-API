require("dotenv").config();


const bcrypt = require("bcrypt");
const crypto = require("crypto");

const { Pool } = require("pg");

const pool = new Pool({
    user: process.env.DB_USER,
    host: process.env.DB_HOST,
    database: process.env.DB_NAME,
    password: process.env.DB_PASSWORD,
    port: process.env.DB_PORT
});

//AUTHENTICATION
//-----------------------------------------------------------------
const hashPassword = (password) => {
    return new Promise((resolve, reject) => {
        bcrypt.hash(password, 10, (err, hash) => {
            err ? reject(err) : resolve(hash)
        })
    })
}

const checkPassword = (reqPassword, foundUser) => {
    return new Promise((resolve, reject) => bcrypt.compare(reqPassword, foundUser.password_digest, (err, res) => {
        if (err) {
            reject(err)
        }
        else if (res) {
            resolve(res)
        } else {
            reject(new Error('Passwords do not match'))
        }
    }))
}



const createUser = (user) => {
    return pool.query('INSERT INTO users (username, password_digest, token) VALUES($1, $2, $3) RETURNING *', [user.username, user.password_digest, user.token]).then((data) => data.rows[0])
}

const findUser = (userReq) => {
    return pool.query('SELECT * FROM users WHERE username = $1', [userReq.username]).then((data) => data.rows[0])
}




const createToken = () => {
    return new Promise((resolve, reject) => {
        crypto.randomBytes(16, (err, data) => {
            err ? reject(err) : resolve(data.toString('hex'))
        })
    })
}

const updateUserToken = (token, user) => {
    return pool.query('UPDATE users SET token = $1 WHERE id = $2 RETURNING id, username, token', [token, user.id])
    .then(data => data.rows[0])
}

const signup = (req, res) => {
    const user = req.body;
    hashPassword(user.password).then((hashedPassword) => {
        user.password_digest = hashedPassword
        delete user.password
    }).then(() => createToken()).then(token => user.token = token).then(() => createUser(user)).then(user => {
        delete user.password_digest
        res.status(201).json({ user })
    })
        .catch((err) => {
            console.error(err);
            res.status(500).json({ error: "Internal Server Error" });
        })
}

const signin = (req, res) => {
    const userReq = req.body;
    let user;

    findUser(userReq).then(foundUser => {
        if (!foundUser) throw new Error('User not found');

        user = foundUser;
        return checkPassword(userReq.password, foundUser)
    }).then(() => createToken()).then(token => updateUserToken(token, user))
        .then(updatedUser => {
            delete updatedUser.password_digest
            res.status(200).json(user)
        })
        .catch((err) => {
            console.error(err);
            res.status(500).json({ error: "Internal Server Error" });
        })
}
//------------------------------------------------------------
//GET TASKS
const getUsers = async (req, res) => {
    const results = await pool.query('SELECT id, username, token FROM users');
    res.status(200).json(results.rows)
}

const findByToken = (token) => {
    return pool.query('SELECT * FROM users WHERE token = $1', [token])
        .then((data) => data.rows[0])
}

const authenticate = (userReq) => {
    return findByToken(userReq.token)
        .then((user) => {
            console.log("User from DB:", user);


            if (!user) return false;

            if (user.username === userReq.username) {
                return true
            } else {
                return false
            }
        })
}

const getTasks = async (req, res) => {
    const userReq = req.body;
    const isAuthenticated = await authenticate(userReq);

    if (isAuthenticated) {
        const results = await pool.query('SELECT * FROM tasks');
        res.status(200).json(results.rows)
    } else {
        return res.status(403).json({ error: "Unauthorized" });
    }
}

const createTasks = async (req, res) => {
    const userReq = req.body;
    const isAuthenticated = await authenticate(userReq);



    if (isAuthenticated) {
        const { title, description, status } = req.body;

        const results = await pool.query('INSERT INTO tasks(title, description, status) VALUES($1, $2, $3) RETURNING *', [title, description, status]);
        res.status(201).json(results.rows)
    } else {
        return res.status(403).json({ error: "Unauthorized" });
    }
}

const updateTasks = async (req, res) => {
    const userReq = req.body;
    const isAuthenticated = await authenticate(userReq);



    if (isAuthenticated) {
        const { status } = req.body;
        const task_id = parseInt(req.params.id)

        const results = await pool.query('UPDATE tasks SET status = $1 WHERE id = $2 RETURNING *', [status, task_id]);
        res.status(200).json(results.rows)
    } else {
        return res.status(403).json({ error: "Unauthorized" });
    }
}

const getTasksByStatus = async (req, res) => {
    const userReq = req.body;
    const isAuthenticated = await authenticate(userReq);


    if (isAuthenticated) {
        const { status } = req.query;


        const results = await pool.query('SELECT * FROM tasks WHERE status = $1', [status]);
        res.status(200).json(results.rows)
    } else {
        return res.status(403).json({ error: "Unauthorized" });
    }
}

const deleteTask = async (req, res) => {
    const userReq = req.body;
    const isAuthenticated = await authenticate(userReq);


    if (isAuthenticated) {
        const task_id = parseInt(req.params.id);


        const results = await pool.query('DELETE FROM tasks WHERE id = $1', [task_id]);
        res.status(204).send()
    } else {
        return res.status(403).json({ error: "Unauthorized" });
    }
}


module.exports = {
    getUsers,
    signup,
    signin,
    getTasks,
    createTasks,
    updateTasks,
    getTasksByStatus,
    deleteTask
}