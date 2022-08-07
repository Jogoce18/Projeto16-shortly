import bcrypt from 'bcrypt';

import db from "../config/db.js";

async function getUserByEmail(email) {
  return db.query(`SELECT * FROM users WHERE email = $1 `, [email]);
}

async function getUserById(id) {
  return db.query(`SELECT * FROM users WHERE id = $1 `, [id]);
}

async function createUser(name, email, plainPassword) {
  const SALT = 10;
  const passwordHash = bcrypt.hashSync(plainPassword, SALT);
  return db.query(`
    INSERT INTO users (name, email, password) 
    VALUES ($1, $2, $3)`, 
    [name, email, passwordHash]);
}


async function getUserAndLinksById(id) {
  return db.query(`
  SELECT u.id, u."shortUrl", u.url, u."visitCount"
  FROM urls u
  JOIN users usr ON u."userId" = usr.id
  WHERE usr.id = $1`, [id]);
}

async function getUrlsRankingByUser() {
  return db.query(`
    SELECT usr.id, usr.name, COUNT(u.id) as "linksCount", SUM(u."visitCount") as "visitCount"
    FROM urls u
    JOIN users usr ON u."userId" = usr.id
    GROUP BY usr.id
    ORDER BY "visitCount" DESC
    LIMIT 10
  `);
}

const usersRepository = {
  createUser,
  getUserById,
  getUserByEmail,
  getUserAndLinksById,
  getUrlsRankingByUser
};

export default usersRepository;