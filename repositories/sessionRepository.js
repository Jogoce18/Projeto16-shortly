import db from "../config/db.js";

async function createSession(token, userId) {
  return db.query(`
   INSERT INTO sessions (token, "userId") VALUES ($1, $2)`, [token, userId]);
}

async function getSessionByToken(token) {
  return db.query(`SELECT *  FROM sessions WHERE token = $1`, [token]);
}

const sessionRepository = {
  createSession,
  getSessionByToken
}

export default sessionRepository;