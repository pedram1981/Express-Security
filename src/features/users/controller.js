import express from "express";
import * as auth from "../../infrastructure/auth/security.js";
import * as service from "./service.js";
import { body, validationResult } from "express-validator";


const router = express.Router();



router.route("/Auth0Token").post(auth.validateRequest, async (req, res) => {
   res.status(400).json({ token:auth.getAccessTokenAuth0()} ); 
});

router.route("/signOut").post(auth.validateAuth0, [
  body("name").trim().escape(),
  body("email").isEmail().normalizeEmail(),
  body("password").isStrongPassword(),
], auth.validateRequest, async(req, res)=> {
  const { name, email, password} = req.body;
  const passToken = await auth.hashPassword({ email, password });
  const result=await service.signOut(name,email, passToken);
  if(result.success)
   return res.status(200).json({ message:result.outcome });
  else
  return res.status(400).json({ eror:result.outcome });
});

router.route("/signIn").post([
  body("name").trim().escape(),
  body("email").isEmail().normalizeEmail(),
  body("password").isStrongPassword(),
], auth.validateRequest,async (req, res) => {
  const { email, password } = req.body;
  const pass = await auth.hashPassword({ email, password });
  const  result= await service.login(email,pass);
  if(result.success){
  const token = await auth.generateToken({ email, password });
  return res.status(200).json({ token });
  }
  else
   return res.status(401).json({ error: "Invalid credentials" });
});

router.route("/profile").get(auth.validateRequest,auth.verifyToken,async (req, res) => {
  const { email } = req.query;

    const  result= await service.profile(email);
    if(result)
    return res.status(200).json({ profile:result.outcome });
     else
     return res.status(401).json({ error: "The profile is not exist" });
});

export default router;
