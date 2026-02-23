import bcrypt from 'bcryptjs';
import { config } from '../config/env.config.js';
import jwt from 'jsonwebtoken';

export const hashPassword = async (
  password: string,
  saltRounds: number = 10,
): Promise<string> => {
  const salt = await bcrypt.genSalt(saltRounds);
  const hashedPassword = await bcrypt.hash(password, salt);
  return hashedPassword;
};

export const comparePassword = async (
  password: string,
  hashedPassword: string,
): Promise<boolean> => {
  const isMatch = await bcrypt.compare(password, hashedPassword);
  return isMatch;
};

export const generateJWT = (id: number): string => {
  const secret = config.JWT_SECRET;

  if (!secret) {
    throw new Error('JWT_SECRET is not defined in environment variables');
  }

  return jwt.sign({ id }, secret, {
    expiresIn: '1d',
  });
};
