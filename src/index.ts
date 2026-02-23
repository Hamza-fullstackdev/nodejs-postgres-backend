import express from 'express';
import rateLimit from 'express-rate-limit';
import helmet from 'helmet';
import compression from 'compression';
import cors from 'cors';
import cookieParser from 'cookie-parser';
import { globalErrorHandler } from './middlewares/global-error.js';
import { config } from './config/env.config.js';

const app = express();

const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 100,
  message: {
    message: 'Too many requests, please try again later.',
    status: 429,
  },
});

// app.set('trust proxy', true);
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());
app.set('etag', false);
app.use((req, res, next) => {
  res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
  res.setHeader('Pragma', 'no-cache');
  res.setHeader('Expires', '0');
  res.setHeader('Surrogate-Control', 'no-store');
  next();
});
app.use(limiter);
app.use(helmet());
app.use(compression({ level: 9 }));
app.use(
  cors({
    origin: ['http://localhost:3000'],
    credentials: true,
    methods: ['GET', 'POST', 'PATCH', 'DELETE', 'OPTIONS'],
  }),
);

import router from './routes/index.js';

app.use('/api/v1', router);

app.listen(config.PORT, () => {
  console.log(`Server is running on PORT: ${config.PORT}`);
});

app.use(globalErrorHandler);
