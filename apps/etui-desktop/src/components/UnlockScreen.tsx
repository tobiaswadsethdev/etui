import React from "react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import type { AuthSessionStatus } from "@/types";

type UnlockScreenProps = {
  authStatus: AuthSessionStatus | null;
  authExpiresText: string | null;
  canUnlockVault: boolean;
  authEmail: string;
  setAuthEmail: (value: string) => void;
  authPassword: string;
  setAuthPassword: (value: string) => void;
  masterPassword: string;
  setMasterPassword: (value: string) => void;
  busy: boolean;
  authBusy: boolean;
  error: string | null;
  handleAuthSignIn: (event: React.FormEvent<HTMLFormElement>) => Promise<void>;
  handleAuthSignOut: () => Promise<void>;
  handleUnlock: (event: React.FormEvent<HTMLFormElement>) => Promise<void>;
};

export function UnlockScreen({
  authStatus,
  authExpiresText,
  canUnlockVault,
  authEmail,
  setAuthEmail,
  authPassword,
  setAuthPassword,
  masterPassword,
  setMasterPassword,
  busy,
  authBusy,
  error,
  handleAuthSignIn,
  handleAuthSignOut,
  handleUnlock,
}: UnlockScreenProps) {
  return (
    <main className="min-h-screen grid place-content-center p-6">
      <Card className="w-full max-w-sm">
        <CardHeader>
          <CardTitle>
            <h1 className="text-[clamp(1.5rem,3.4vw,2.2rem)] font-semibold tracking-tight">
              etui Desktop
            </h1>
          </CardTitle>
          <CardDescription>Unlock your local encrypted vault.</CardDescription>
        </CardHeader>
        <CardContent className="flex flex-col gap-4">
          {authStatus?.configured ? (
            <div className="flex flex-col gap-3">
              <h2 className="text-[1.05rem] font-semibold">Supabase Account</h2>
              {authStatus.authenticated ? (
                <>
                  <p className="text-sm text-slate-600 mt-0">
                    Signed in as{" "}
                    <strong>{authStatus.email ?? authStatus.userId ?? "user"}</strong>
                    {authExpiresText ? ` (${authExpiresText})` : ""}.
                  </p>
                  <Button variant="outline" type="button" onClick={handleAuthSignOut} disabled={authBusy}>
                    {authBusy ? "Signing out..." : "Sign Out"}
                  </Button>
                </>
              ) : (
                <form className="flex flex-col gap-2.5" onSubmit={handleAuthSignIn}>
                  <Label htmlFor="auth-email">Email</Label>
                  <Input
                    id="auth-email"
                    type="email"
                    autoComplete="email"
                    value={authEmail}
                    onChange={(event) => setAuthEmail(event.target.value)}
                    required
                  />
                  <Label htmlFor="auth-password">Password</Label>
                  <Input
                    id="auth-password"
                    type="password"
                    autoComplete="current-password"
                    value={authPassword}
                    onChange={(event) => setAuthPassword(event.target.value)}
                    required
                  />
                  <Button variant="outline" type="submit" disabled={authBusy}>
                    {authBusy ? "Signing in..." : "Sign In to Supabase"}
                  </Button>
                </form>
              )}
            </div>
          ) : (
            <p className="text-sm text-slate-500 mt-0">
              Supabase sync is not configured in environment.
            </p>
          )}

          {canUnlockVault ? (
            <form className="flex flex-col gap-2.5" onSubmit={handleUnlock}>
              <Label htmlFor="master-password">Master password</Label>
              <Input
                id="master-password"
                type="password"
                value={masterPassword}
                onChange={(event) => setMasterPassword(event.target.value)}
                autoComplete="current-password"
                placeholder="Enter master password"
                required
              />
              <Button type="submit" disabled={busy}>
                {busy ? "Unlocking..." : "Unlock"}
              </Button>
            </form>
          ) : (
            <p className="text-sm text-slate-500 mt-0">Sign in first to access your vault.</p>
          )}

          {error ? <p className="text-red-700 text-sm">{error}</p> : null}
        </CardContent>
      </Card>
    </main>
  );
}
