require("dotenv").config();
const express = require("express");
const User = require('./models/user.js');
const PORT = process.env.PORT;

const app = express();

app.use(express.json());
app.use(express.urlencoded({ extended: true }))

app.listen(PORT, () => console.log(`Server running on ${PORT}.......`))

app.get('/', User.getUsers);
app.post('/signup', User.signup);
app.post('/signin', User.signin);

app.get('/tasks', (req, res) => {
    if (req.query.status) {
        User.getTasksByStatus(req, res);
    } else {
        User.getTasks(req, res);
    }
});
app.post('/tasks', User.createTasks);
app.put('/tasks/:id', User.updateTasks);
app.delete('/tasks/:id', User.deleteTask);

