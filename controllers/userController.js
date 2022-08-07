import urlsRepository from '../repositories/urlsRepository.js';
import usersRepository from '../repositories/userRepository.js';

export async function createUser(req, res) {
  const user = req.body;

  try {
    const existingUsers = usersRepository.getUserByEmail(user.email)
    if (existingUsers.rowCount > 0) {
      return res.sendStatus(409); // conflict
    }

    const {name, email, password} = user;
    await usersRepository.createUser(name, email, password);

    res.sendStatus(201); // created
  } catch (error) {
    console.log(error);
    return res.sendStatus(500); // server error
  }
}

export async function getUserById(req, res) {
  const { id } = req.params;
  const { user } = res.locals;

  if(id != user.id ) {
    return res.sendStatus(401); // unauthorized
  }

  try {
    const visitResult = await urlsRepository.getVisitCountByUser(id);
    const [visitCount] = visitResult.rows;

    const urlsResult = await urlsRepository.getURLSbyUser(id);
    const userUrls = urlsResult.rows;

    res.send({
      id: user.id,
      name: user.name,
      visitCount: visitCount.sum || 0,
      shortenedUrls: userUrls
    });
  } catch (error) {
    console.log(error);
    return res.sendStatus(500); // server error
  }
}

export async function getRanking(req, res) {
  try {
    const result = await usersRepository.getUrlsRankingByUser();
    res.send(result.rows);
  } catch (error) {
    console.log(error);
    return res.sendStatus(500); // server error
  }
}