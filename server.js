import express, {raw} from 'express';
import { expressjwt } from "express-jwt";
import * as dotenv from 'dotenv';
import knex from 'knex';
import {users} from './models/users.js';
import {usersPasswords} from './models/users_passwords.js';
import * as bodyParser from 'body-parser';

dotenv.config();

const config = {
    client: 'sqlite3',
    connection: {
        filename: './.data/sec_password.sqlite3',
    },
    migrations: {
        tableName: 'migrations'
    },
    pool: { min: 0, max: 7 }
};
const db = knex(config);

const app = express();

app.use(
    expressjwt({
        secret: process.env.JWT_SECRET,
        algorithms: ["HS256"],
    }).unless({ path: ["/login", "/signup", '/'] })
);

app.use(bodyParser.default.json());

app.get('/', (req, res) => {
   res.status(200).json({message: "welcome"});
});
app.post('/signup', async (req, res, next) => {
    try {
        const created = await new users(db).createUser(req.body);
        if (!created) {
            return res.status(400).json({message: 'Sign up failed'});
        }
        res.json({message: 'done', status: 200});
    } catch (e) {
        console.error(e);
        res.status(500).json({message: 'internal_server_error'})
    }
});

app.post('/login', async (req, res, next) => {
    try {
        const loginObj = await new users(db).login(req.body);
        if (!loginObj) {
            return res.status(403).json({message: 'Invalid username or password'});
        }
        res.json({message: 'done', payload: loginObj, status: 200});
    } catch (e) {
        console.error(e);
        res.status(500).json({message: 'internal_server_error'})
    }
});

app.post('/save-password', async (req, res, next) => {
    try {
        req.body.user_id = req.auth.id;
        const obj = await new usersPasswords(db).create(req.body);
        if (!obj) {
            return res.status(403).json({message: 'Invalid key'});
        }
        res.json({message: 'done', status: 200});
    } catch (e) {
        console.error(e);
        res.status(500).json({message: 'internal_server_error'})
    }
});

app.post('/list', async (req, res, next) => {
    try {
        req.body.user_id = req.auth.id;
        const obj = await new usersPasswords(db).list(req.body);
        if (!obj) {
            return res.status(403).json({message: 'Invalid key'});
        }
        res.json({message: 'success', data: obj, status: 200});
    } catch (e) {
        console.error(e);
        res.status(500).json({message: 'internal_server_error'})
    }
});

app.listen(process.env.PORT || 3000, () =>
    console.log('App listening on port 3000!'),
);