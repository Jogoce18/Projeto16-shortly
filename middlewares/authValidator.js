import sessionRepository from "../repositories/sessionRepository.js";
import userRepository from "../repositories/userRepository.js";

export async function validateToken(req, res, next) {
  const authorization = req.headers.authorization;
  const token = authorization?.replace("Bearer ", "");
  if (!token) {
    return res.send(401).status("No token."); // unauthorized
  }

  try {
    const { rows:sessions } = await sessionRepository.getSessionByToken(token);
    const [session] = sessions;
    if (!session) {
      return res.send(401).send("Session not found."); // unauthorized
    }

    const { rows: users } = await userRepository.getUserById(session.userId);
    const [user] = users;
    if (!user) {
      return res.send(401).send("User not found."); // unauthorized
    }
  
    res.locals.user = user;
    next();
  } catch (error) {
    console.log(error);
    return res.sendStatus(500); // server error
  }  
}