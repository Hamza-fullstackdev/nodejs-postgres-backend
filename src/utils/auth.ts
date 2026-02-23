import bcrypt from 'bcryptjs';

export const hashPassword = async (password: string, saltRounds: number = 10): Promise<string> => {
  const salt = await bcrypt.genSalt(saltRounds);
  const hashedPassword = await bcrypt.hash(password, salt);
  return hashedPassword;
};
export const comparePassword = async (password: string, hashedPassword: string): Promise<boolean> => {
  const isMatch = await bcrypt.compare(password, hashedPassword);
  return isMatch;
};
