import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';

export class users {
    constructor(db) {
        this.db = db;
        this.usersTable = () => db('users')
    }

    async createUser(obj) {
        const {db} = this;
        const trx = await db.transaction();
        try {
            const {name, email, password, encryptionKey} = obj;
            const rec = await trx('users')
                .insert({
                    name,
                    password: await this.hashStr(password),
                    password_encryption_key: await this.hashStr(encryptionKey),
                    email
                }, 'id');
            await trx.commit();
            return rec;
        } catch (e) {
            console.error(e);
            await trx.rollback();
            return false;
        }
    }

    async login(obj) {
        const {email, password} = obj;
        const {usersTable} = this;
        const userRecord = await usersTable().where('email', email).first();
        if (!userRecord) {
            return false;
        }
        const matched = await bcrypt.compare(password, userRecord.password);
        if (!matched) {
            return false;
        }
        return {userRecord, token: await this.genJwt(userRecord)};
    }

    async hashStr(str) {
        const salt = await bcrypt.genSalt(10);
        return bcrypt.hash(str, salt);
    }

    genJwt(obj) {
        return new Promise((resolve, reject) => {
            jwt.sign({ id: obj.id}, process.env.JWT_SECRET, { algorithm: 'HS256' }, function(err, token) {
                if (err) {
                    return reject(err);
                }
                resolve(token);
            });
        });
    }

   async  get(id) {
        const {usersTable} = this;
        return usersTable(this.db).where('id', id).first();
    }
}