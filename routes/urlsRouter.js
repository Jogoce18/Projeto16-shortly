import { Router } from "express";

import urlSchema from "./../schemas/urlSchema.js";
import { validateSchema } from "./../middlewares/ValidatorSchema.js";
import { validateToken } from "./../middlewares/authValidator.js";
import {shortenURL, getURLById, deleteURL, openShortUrl} from "./../controllers/urlsController.js";

const urlsRouter = Router();

urlsRouter.post("/urls/shorten", validateSchema(urlSchema), validateToken, shortenURL);
urlsRouter.get("/urls/:id", getURLById);
urlsRouter.delete("/urls/:id", validateToken, deleteURL);
urlsRouter.get('/urls/open/:shortUrl', openShortUrl);

export default urlsRouter;