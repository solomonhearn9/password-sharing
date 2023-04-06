# Project setup
1. npm install

2. create .env file in the project root and put below

       PORT=3000  
       JWT_SECRET=replace_with_random_secret_value

3. Install sqlite3. Copy template_db/sec_password.sqlite3 to .data/sec_password.sqlite3

4. Update database with correct schema


	    knex migrate:up --client sqlite3 --connection .data/sec_password.sqlite3
5. To run the project use `npm start`