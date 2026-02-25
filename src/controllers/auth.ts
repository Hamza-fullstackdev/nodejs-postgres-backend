import type { Request, Response, NextFunction } from 'express';
import type { LoginInput, RegisterInput, User } from '../types/auth.js';
import errorHandler from '../utils/app-error.js';
import {
  forgotPasswordSchema,
  loginSchema,
  registerSchema,
} from '../schemas/auth.js';
import db from '../config/connection.js';
import { comparePassword, generateJWT, hashPassword } from '../utils/auth.js';
import { sendEmail } from '../config/smtp.js';
import { nanoid } from 'nanoid';
import { config } from '../config/env.config.js';
import crypto from 'node:crypto';

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
    const authCookie = config.AUTH_COOKIE!;

    res.cookie(authCookie, token, {
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

export const logout = async (
  req: Request,
  res: Response,
  next: NextFunction,
): Promise<void> => {
  if (!req.user) {
    return next(errorHandler(401, 'Unauthorized user'));
  }
  try {
    res.clearCookie(config.AUTH_COOKIE!, {
      httpOnly: true,
      secure: config.NODE_ENV === 'production',
      sameSite: 'strict',
    });

    res.status(200).json({
      success: true,
      message: 'Logout successful',
    });
  } catch (error) {
    next(error);
  }
};

export const verifyEmail = async (
  req: Request,
  res: Response,
  next: NextFunction,
): Promise<void> => {
  const rawToken = Array.isArray(req.query.token)
    ? req.query.token[0]
    : req.query.token;
  const rawEmail = Array.isArray(req.query.email)
    ? req.query.email[0]
    : req.query.email;

  const token = typeof rawToken === 'string' ? rawToken : undefined;
  const email = typeof rawEmail === 'string' ? rawEmail : undefined;

  if (!token || !email) {
    return next(errorHandler(400, 'Token and email are required'));
  }

  try {
    const isUserExists = await db.query(
      'SELECT * FROM users WHERE email = $1 AND verify_token = $2',
      [email, token],
    );
    if (!isUserExists.rowCount || isUserExists.rowCount < 1) {
      return next(errorHandler(400, 'Invalid token or token has expired'));
    }

    const user: User = isUserExists.rows[0];

    if (user.verify_token_expiry && user.verify_token_expiry < new Date()) {
      return next(errorHandler(400, 'Invalid token or token has expired'));
    }

    const updateUser = await db.query(
      'UPDATE users SET is_verified = $1, is_active = $2, verify_token = $3, verify_token_expiry = $4 WHERE email = $5 AND verify_token = $6 RETURNING id',
      [true, true, null, null, email, token],
    );
    if (!updateUser.rowCount || updateUser.rowCount < 1) {
      res.status(500).json({
        message:
          'We are unable to verify your email right now, please try again later',
      });
    }
    res.status(200).json({ message: 'Email verified successfully' });
  } catch (error) {
    next(error);
    console.log(error);
  }
};

export const forgetPassword = async (
  req: Request,
  res: Response,
  next: NextFunction,
): Promise<void> => {
  const parsed = forgotPasswordSchema.safeParse(req.body);

  if (!parsed.success) {
    const errorMessage =
      parsed.error.issues[0]?.message ?? 'Invalid request data';
    return next(errorHandler(400, errorMessage));
  }

  const { email } = parsed.data;

  try {
    const isUserExist = await db.query('SELECT * FROM users WHERE email = $1', [
      email,
    ]);
    if (!isUserExist.rowCount || isUserExist.rowCount < 1) {
      return next(
        errorHandler(400, "Sorry we can't find this email in out records"),
      );
    }
    const user: User = isUserExist.rows[0];

    const resetToken = crypto.randomBytes(32).toString('hex');
    const hashedToken = crypto
      .createHash('sha256')
      .update(resetToken)
      .digest('hex');
    const resetTokenExpiry = new Date(Date.now() + 3600000);

    await db.query(
      'UPDATE users SET reset_token = $1, reset_token_expiry = $2 WHERE email = $3',
      [hashedToken, resetTokenExpiry, user.email],
    );

    const resetLink = `${config.UI_BASE_URL}/reset-password/${resetToken}`;
    await sendEmail({
      to: email,
      subject: 'Password Reset',
      text: `Reset your password using this link: ${resetLink}`,
    });

    res.status(200).json({
      message:
        'A password reset link has been sent to your email. Please check your inbox and follow the instructions to reset your password.',
    });
  } catch (error) {
    next(error);
  }
};

export const resetPassword = async (
  req: Request,
  res: Response,
  next: NextFunction,
): Promise<void> => {
  const rawToken = req.params.token;
  const token = Array.isArray(rawToken) ? rawToken[0] : rawToken;
  const { password } = req.body as { password?: string };

  if (!token || !password) {
    return next(errorHandler(400, 'Token and new password are required'));
  }

  try {
    const hashedToken = crypto.createHash('sha256').update(token).digest('hex');

    const userResult = await db.query<User>(
      'SELECT id FROM users WHERE reset_token = $1 AND reset_token_expiry > $2',
      [hashedToken, new Date(Date.now())],
    );

    if (!userResult.rowCount || userResult.rowCount < 1) {
      return next(errorHandler(400, 'Invalid or expired token'));
    }

    const user = userResult.rows[0] as User;

    const hashedPassword = await hashPassword(password);

    await db.query(
      'UPDATE users SET password = $1, reset_token = $2, reset_token_expiry = $3 WHERE id = $4',
      [hashedPassword, null, null, user.id],
    );

    res.status(200).json({ message: 'Password reset successful.' });
  } catch (error) {
    next(error);
  }
};
