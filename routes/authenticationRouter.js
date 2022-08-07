import { Router } from "express";
import userSchema from "../schemas/userSchema.js";
import loginSchema from "./../schemas/loginSchema.js";
import { login } from "./../controllers/authController.js";
import { createUser } from "../controllers/userController.js";
import { validateSchema } from "./../middlewares/ValidatorSchema.js";

const authRouter = Router();

authRouter.post('/signup', validateSchema(userSchema), createUser);
authRouter.post('/signin', validateSchema(loginSchema), login);

export default authRouter;