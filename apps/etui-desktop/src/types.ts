export type SessionInfo = {
  vaultId: string;
  entryCount: number;
};

export type AuthSessionStatus = {
  configured: boolean;
  authenticated: boolean;
  userId: string | null;
  email: string | null;
  expiresInSeconds: number | null;
};

export type EntrySummary = {
  id: string;
  title: string;
  username: string;
  updatedAt: string;
};

export type EntryDetail = {
  id: string;
  title: string;
  username: string;
  password: string;
  notes: string;
  updatedAt: string;
};

export type NewEntryInput = {
  title: string;
  username: string;
  password: string;
  notes: string;
};
