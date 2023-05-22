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
app.post('/signup', async (req, res) => {
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

app.post('/login', async (req, res) => {
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

app.post('/save-password', async (req, res) => {
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

app.post('/share-password', async (req, res) => {
    try {
        const passwordId = req.body.passwordId;
        const encKey = req.body.encKey;
        const email = req.body.inviteeEmail;
        const inviteeUser = await new users(db).getByEmail(email);
        if (!inviteeUser) {
          return res.status(400).json({message: 'The user with whom you want to share password does not exist'});
        }
        const passwordRow = await new usersPasswords(db).getPasswordById(passwordId, encKey);
        if (!passwordRow) {
            return res.status(403).json({message: 'Invalid password id'});
        }
        const usersPasswordsObj = new usersPasswords(db);
        await usersPasswordsObj.createActual({
          user_id: inviteeUser.id,
          shared_by_user_id: req.auth.id,
          password_label: passwordRow.password_label,
          url: passwordRow.url,
          encKey: process.env['SYS_ENC_KEY'],
          login: usersPasswordsObj.encrypt(passwordRow.login, process.env['SYS_ENC_KEY']),
          password: usersPasswordsObj.encrypt(passwordRow.password, process.env['SYS_ENC_KEY'])
        });
        res.json({message: 'done', status: 200});
    } catch (e) {
        console.error(e);
        res.status(500).json({message: 'internal_server_error'})
    }
});

app.post('/list', async (req, res) => {
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

app.post('/list-shared-passwords', async (req, res) => {
    try {
        req.body.user_id = req.auth.id;
        const obj = await new usersPasswords(db).listShared(req.body);
        if (!obj) {
            return res.status(403).json({message: 'Invalid key'});
        }
        res.json({message: 'success', data: obj, status: 200});
    } catch (e) {
        console.error(e);
        res.status(500).json({message: 'internal_server_error'})
    }
});


app.delete('/user-password/:id', async (req, res) => {
    try {
        req.body.user_id = req.auth.id;
        const numDeleted = await new usersPasswords(db).delete({
            user_id: req.auth.id,
            user_password_id: req.params.id
        });
        if (!numDeleted && numDeleted !== 0) {
            return res.status(403).json({message: 'Invalid key'});
        }
        res.json({message: 'success', data: `Deleted ${numDeleted} record(s)`, status: 200});
    } catch (e) {
        console.error(e);
        res.status(500).json({message: 'internal_server_error'})
    }
});

app.listen(process.env.PORT || 3000, () =>
    console.log('App listening on port 3000!'),
);