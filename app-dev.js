import express from "express";
import url from "url";
import cors from "cors";
import helmet from "helmet";
import rateLimit from "express-rate-limit";
import dotenvSafe from "dotenv-safe";
import path from "path";
import userCtl from "./src/features/users/controller.js";



const app = express();

//dotenv
const __filename = url.fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

try {
  dotenvSafe.config({
    allowEmptyValues: true,
    example: path.resolve(__dirname, ".env.example"),
    path: path.resolve(__dirname, ".env"),
  });
} catch (error) {
  if (error instanceof dotenvSafe.MissingEnvVarsError) {
    console.error("Missing environment variables:", error.missing);
    process.exit(1);
  } else {
    throw error;
  }
}

// Authentication
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Reduction of vulnerability attacks
app.use(express.urlencoded({ limit: "10mb", parameterLimit: 10000, extended: true }));

// Collection of input
app.use(express.json({ limit: "10mb" }));

// Defense from attacks
app.use((req, res, next) => {
  req.body = req.body.replace(/<script>.*?<\/script>/g, "");
  next();
});

// Cleaning of the user input
app.use((req, res, next) => {
  req.body = req.body.replace(/<.*?>/g, "");
  next();
});

//security-related HTTP headers
app.use(helmet());

//Cors
app.use(cors({
  origin: [process.env.address],
  methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
  allowedHeaders: ["Origin", "X-Requested-With", "Content-Type", "Accept", "x-access-token"],
  credentials: true,
  maxAge: 86400
}));

// Rate-limiting
const blockedIPs = new Set();
const rateLimitOptions = {
  max: 4, // Max requests per window per IP
  timeWindow: "1 minute", // Time window in milliseconds
  keyGenerator: (req) => req.ip, // Use the client's IP address as the key
  errorResponseBuilder: (req) => {
    const ip = req.ip;
    if (!blockedIPs.has(ip)) {
      blockedIPs.add(ip);
      app.log.error({ error: new Error("Too many requests from this IP address"), ip }, "Rate limit exceeded");
      app.addHook("onResponse", (request, reply, done) => {
        reply.header("X-Ratelimit-Block", "true");
        done();
      });
    }
    return { error: "Too many requests from this IP address" };
  },
};

app.use(rateLimit(rateLimitOptions));

// API Routes
app.use("/api/v1/user", userCtl);


// Start the server
const port = process.env.port;
app.listen(port, () => {
  console.log(`Server started on port ${port}`);
});