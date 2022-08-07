import {Router} from "express";
import urlsRouter from "./urlsRouter.js";
import usersRouter from "./usersRouter.js";
import authRouter from "./authenticationRouter.js";

const router = Router();

router.use(authRouter);
router.use(usersRouter);
router.use(urlsRouter);

export default router;