import bcrypt from 'bcryptjs';
import crypto from "crypto";
import {users} from "./users.js";

export class usersPasswords {
    constructor(db) {
        this.db = db;
        this.table = () => db('users_passwords')
    }

    async create(obj) {
        const {db} = this;
        const valid  = await this.validateEncKey(obj.encKey, obj.user_id);
        if (!valid) {
            return false;
        }
        obj.login = this.encrypt(obj.login, obj.encKey);
        obj.password = this.encrypt(obj.password, obj.encKey);
        obj.shared_by_user_id = null;
        return this.createActual(obj);
    }
  
   async createActual(obj) {
     const {db} = this;
     const trx = await db.transaction();
     try {
       const row = {
                user_id: obj.user_id,
                shared_by_user_id: obj.shared_by_user_id,
                password_label: obj.password_label,
                url: obj.url,
                login: obj.login,
                password: obj.password,
            };
            const rec = await trx('users_passwords')
                .insert(row, 'id');
            await trx.commit();
            return rec;
       } catch (e) {
       // console.error(e);
            await trx.rollback();
            throw e;
       }
   }

    encrypt(str, key) {
        const algorithm = 'aes-256-ctr';
        const iv = crypto.randomBytes(16);
        const encKey = crypto.createHash('sha256').update(String(key)).digest('base64').slice(0, 32)
        const cipher = crypto.createCipheriv(algorithm, encKey, iv);
        let crypted = cipher.update(str,'utf-8',"base64") + cipher.final("base64");
        return `${crypted}-${iv.toString('base64')}`;
    }

    decrypt(encStr, key) {
        const algorithm = 'aes-256-ctr';
        const encArr = encStr.split('-');
        const encKey = crypto.createHash('sha256').update(String(key)).digest('base64').slice(0, 32);
        const decipher = crypto.createDecipheriv(algorithm, encKey, Buffer.from(encArr[1], 'base64'));
        let decrypted = decipher.update(encArr[0], 'base64', 'utf-8');
        decrypted += decipher.final('utf-8');
        return decrypted;
    }

    async validateEncKey(key, userId) {
        const usersModel = new users(this.db);
        const userObj = await usersModel.get(userId);
        return await bcrypt.compare(key, userObj.password_encryption_key);
    }

    async list(obj) {
        const {table} = this;
        const {encKey, user_id} = obj;
        const results = await table(this.db).where('user_id', user_id).whereNull('shared_by_user_id');
        return results.map( (row) => {
            row['login'] =  this.decrypt(row['login'], encKey);
            row['password'] =  this.decrypt(row['password'], encKey);
            return row;
        });
    }
  
    async listShared(obj) {
        const {table} = this;
        const {encKey, user_id} = obj;
        const results = await table(this.db).where('user_id', user_id).whereNotNull('shared_by_user_id');
        return results.map( (row) => {
            row['login'] =  this.decrypt(row['login'], process.env['SYS_ENC_KEY']);
            row['password'] =  this.decrypt(row['password'], process.env['SYS_ENC_KEY']);
            return row;
        });
    }

    async delete(obj) {
        const {table} = this;
        const {user_password_id, user_id} = obj;
        return await table(this.db).where('id', user_password_id).where('user_id', user_id).del();
    }
  
    async getPasswordById(passwordId, encKey) {
      const {table} = this;
      const passwordRow = await table(this.db).where('id', passwordId).first();
      if (!passwordRow) {
        return false;
      }
      passwordRow.login = this.decrypt(passwordRow.login, encKey);
      passwordRow.password = this.decrypt(passwordRow.password, encKey);
      return passwordRow;
    }
}