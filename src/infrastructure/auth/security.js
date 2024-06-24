import { body, validationResult } from "express-validator";
import jwt from "jsonwebtoken";
import bcrypt from "bcrypt";
import  jwksClient from "jwks-rsa";
import  axios from "axios";

//-------------------- AUTH0 ------------------------

const client = jwksClient({
  jwksUri: `https://${process.env.AUTH0_DOMAIN}/.well-known/jwks.json`
});

function getKey(header, callback) {
  client.getSigningKey(header.kid, function(err, key) {
    if (err) {
      callback(err);
    } else {
      const signingKey = key.publicKey || key.rsaPublicKey;
      callback(null, signingKey);
    }
  });
}

export const validateAuth0 = (req, res, next) => {
  const authHeader = req.headers.authorization;
  const token = authHeader && authHeader.split(" ")[1];

  if (!token) {
    return res.status(401).json({ error: "Access denied. No token provided." });
  }

  jwt.verify(token, getKey, {
    audience: process.env.AUTH0_AUDIENCE,
    issuer: `https://${process.env.AUTH0_DOMAIN}/`,
    algorithms: ["RS256"]
  }, (err, decoded) => {
    if (err) {
      return res.status(403).json({ error: "Invalid token" });
    }

    req.user = decoded;
    next();
  });
};

export const getAccessTokenAuth0 = async () => {
  try {
    const response = await axios.post(`https://${process.env.AUTH0_DOMAIN}/oauth/token`, {
      client_id: process.env.AUTH0_CLIENT_ID,
      client_secret: process.env.AUTH0_CLIENT_SECRET,
      audience: process.env.AUTH0_AUDIENCE,
      grant_type: "client_credentials"
    }, {
      headers: {
        "Content-Type": "application/json"
      }
    });

    return response.data.access_token;
  } catch (error) {
    console.error("Error obtaining access token:", error);
    throw new Error("Failed to obtain access token");
  }
};

//------------------- JWT --------------------------------

export const verifyToken =async(req, res, next) => {
        const token = getBearerToken(req);
        if (!token) {
            return   res.status(400).json({ errors: "Missing Bearer token" });
        }
        
        jwt.verify(token, process.env.JWT_SECRET, (err) => {
            if (err) {
                res.status(400).json({ errors: "Invalid token" });
            } 
          });
          next();
        };

            
          
  function getBearerToken(request) {
    const { authorization } = request.headers;
    if (!authorization) return null;
  
    const [scheme, token] = authorization.split(" ");
    if (scheme !== "Bearer") return null;
  
    return token;
  }

  export const createToken=(user)=> {
    const options = {
      algorithm: "HS256",
      expiresIn: "1h"
    };
    const token = jwt.sign(user, process.env.JWT_SECRET,options);
    return token;
  };
  //-------------------- salt and pepeer --------------------------------
    export const hashPassword=async (password) => {
           
            // Add the pepper and saltto the password
           const pepper=process.env.pepper;
           const salt = process.env.SALT;
           const saltedPassword = password + pepper;
       
           // Hash the salted password with the generated salt
           const hashedPassword = await bcrypt.hash(saltedPassword, salt);
       
           return hashedPassword;
         };
  
  //----------------  Validate request ---------------

  export const validateRequest = (req, res, next) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }
    next();
  };


