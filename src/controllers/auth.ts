import type { Request, Response, NextFunction } from 'express';
import type { LoginInput, RegisterInput, User } from '../types/auth.js';
import errorHandler from '../utils/app-error.js';
import { loginSchema, registerSchema } from '../schemas/auth.js';
import db from '../config/connection.js';
import { comparePassword, generateJWT, hashPassword } from '../utils/auth.js';
import { sendEmail } from '../config/smtp.js';
import { nanoid } from 'nanoid';
import { config } from '../config/env.config.js';

export const register = async (
  req: Request,
  res: Response,
  next: NextFunction,
): Promise<void> => {
  const parsed = registerSchema.safeParse(req.body);

  if (!parsed.success) {
    const errorMessage =
      parsed.error.issues[0]?.message ?? 'Invalid request data';
    return next(errorHandler(400, errorMessage));
  }

  const { username, email, password, role }: RegisterInput = parsed.data;

  try {
    const verifyToken = nanoid();
    const verifyTokenExpiry = new Date(Date.now() + 3600000);
    const verifyUrl = `${config.UI_BASE_URL}/verify-email?token=${verifyToken}&email=${email}`;

    const isUserExist = await db.query(
      'SELECT id FROM users WHERE username = $1 OR email = $2',
      [username, email],
    );

    if (isUserExist.rowCount && isUserExist.rowCount > 0) {
      return next(errorHandler(400, 'Username or email already exists'));
    }

    const hashedPassword = await hashPassword(password);

    try {
      await sendEmail({
        to: email,
        subject: 'Chatapp - Verify your email',
        text: `Hi ${username}, welcome to chatapp \nPlease click the link below to verify your email address:\n${verifyUrl}\n\nIf you did not request this email, please ignore it.`,
      });
    } catch (error: any) {
      if (error.code === 'ESOCKET') {
        return next(
          errorHandler(
            500,
            'We are unable to send email at the moment, please try with another email account or try again later',
          ),
        );
      }
      return next(error);
    }

    await db.query(
      `INSERT INTO users (username, email, password, role, verify_token, verify_token_expiry) 
         VALUES ($1, $2, $3, $4, $5, $6)`,
      [username, email, hashedPassword, role, verifyToken, verifyTokenExpiry],
    );

    res.status(201).json({
      status: 201,
      message:
        'Please check your email! We have sent you a verification link. Once you verify your email, you can log in to your account.',
    });
  } catch (error: any) {
    next(error);
  }
};

export const login = async (
  req: Request,
  res: Response,
  next: NextFunction,
): Promise<void> => {
  const parsed = loginSchema.safeParse(req.body);

  if (!parsed.success) {
    const errorMessage =
      parsed.error.issues[0]?.message ?? 'Invalid request data';
    return next(errorHandler(400, errorMessage));
  }

  const { email, password }: LoginInput = parsed.data;

  try {
    const result = await db.query('SELECT * FROM users WHERE email = $1', [
      email,
    ]);

    if (!result.rowCount || result.rowCount < 1) {
      return next(errorHandler(400, 'Invalid credentials'));
    }

    const user: User = result.rows[0];

    const isPasswordValid = await comparePassword(password, user.password);
    if (!isPasswordValid) {
      return next(errorHandler(400, 'Invalid credentials'));
    }

    if (!user.is_verified) {
      return next(
        errorHandler(403, 'Please verify your email before logging in'),
      );
    }

    if (!user.is_active) {
      return next(errorHandler(403, 'Your account has been deactivated'));
    }

    const token = generateJWT(user.id);

    res.cookie('token', token, {
      httpOnly: true,
      secure: config.NODE_ENV === 'production',
      sameSite: 'strict',
      maxAge: 24 * 60 * 60 * 1000,
    });

    res.status(200).json({
      success: true,
      message: 'Login successful',
      redirect: user.role === 'user' ? '/app' : '/admin/dashboard',
      user: {
        id: user.id,
        username: user.username,
        email: user.email,
        role: user.role,
        is_verified: user.is_verified,
      },
    });
  } catch (error) {
    next(error);
  }
};
