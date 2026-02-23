import type { Request, Response, NextFunction } from 'express';
import type { RegisterInput } from '../types/auth.js';
import errorHandler from '../utils/app-error.js';
import { registerSchema } from '../schemas/auth.js';
import db from '../config/connection.js';
import { hashPassword } from '../utils/auth.js';

export const register = async (req: Request, res: Response, next: NextFunction): Promise<void> => {
  const parsed = registerSchema.safeParse(req.body);

  if (!parsed.success) {
    const errorMessage = parsed.error.issues[0]?.message ?? 'Invalid request data';
    return next(errorHandler(400, errorMessage));
  }

  const { username, email, password, role }: RegisterInput = parsed.data;

  try {
    const isUserExist = await db.query('SELECT id FROM users WHERE username = $1 OR email = $2', [username, email]);
    if (isUserExist.rowCount && isUserExist.rowCount > 0) {
      return next(errorHandler(409, 'Username or email already exists'));
    }
    const hashedPassword = await hashPassword(password);

    await db.query(
      `INSERT INTO users (username, email, password, role) 
         VALUES ($1, $2, $3, $4)`,
      [username, email, hashedPassword, role],
    );
    res.status(201).json({
      success: true,
      message: 'User registered successfully',
    });
  } catch (error) {
    next(error);
  }
};
