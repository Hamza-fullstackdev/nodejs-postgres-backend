export type UserRole = 'admin' | 'user';

export type User = {
  id: number;
  username: string;
  email: string;
  password: string;
  role: UserRole;
  is_active: boolean;
  is_verified: boolean;
  verify_token: string | null;
  verify_token_expiry: Date | null;
  reset_token: string | null;
  reset_token_expiry: Date | null;
  created_at: Date;
  updated_at: Date;
};

export type RegisterInput = Pick<User, 'username' | 'email' | 'password' | 'role'>;

export type LoginInput = Pick<User, 'email' | 'password'>;
