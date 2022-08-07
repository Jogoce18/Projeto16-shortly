import db from "../config/db.js"

async function createShortURL(url, shortUrl, id) {
  return db.query(`
    INSERT INTO urls(url, "shortUrl", "userId")
    VALUES ($1, $2, $3)
  `, [url, shortUrl, id])
}

async function getByShortURL(shortUrl) {
  return db.query(`
    SELECT * 
    FROM urls 
    WHERE "shortUrl" = $1`, 
    [shortUrl])
}

async function getURLById(id) {
  return db.query(`SELECT * FROM urls WHERE id = $1`, [id]);
}

async function incrementURLVisitCount(urlId) {
  return db.query(`
    UPDATE urls
    SET "visitCount" = "visitCount" + 1
    WHERE id = $1`, 
    [urlId]);
}

async function deleteURL(id) {
  return db.query('DELETE FROM urls WHERE id=$1', [id])
}

async function getURLSbyUser(userId) {
  return db.query(`SELECT * FROM urls WHERE urls."userId" = $1`, [userId]);
}

async function getVisitCountByUser(userId) {
  return db.query(`SELECT SUM(u."visitCount") FROM urls u WHERE u."userId" = $1`, [userId]);
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

const urlsRepository = {
  createShortURL,
  getByShortURL,
  incrementURLVisitCount,
  deleteURL,
  getURLById,
  getUrlsRankingByUser,
  getVisitCountByUser,
  getURLSbyUser
};

export default urlsRepository;