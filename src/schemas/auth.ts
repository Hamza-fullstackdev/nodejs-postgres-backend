import z from 'zod';

export const registerSchema = z.object({
  username: z
    .string()
    .min(3, 'Username must be at least 3 characters')
    .max(20, 'Username must be at most 20 characters')
    .regex(/^[a-z_]+$/, 'Username can only contain lowercase letters and underscores'),
  email: z.email('Please provide a valid email address'),
  password: z
    .string()
    .min(6, 'Password must be at least 6 characters')
    .max(100, 'Password must be at most 100 characters'),
  role: z.enum(['admin', 'user']).default('user'),
});
