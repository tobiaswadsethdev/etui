import React from "react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import type { AuthSessionStatus, EntrySummary, EntryDetail, NewEntryInput } from "@/types";

type WorkspaceViewProps = {
  entries: EntrySummary[];
  selectedEntry: EntryDetail | null;
  newEntry: NewEntryInput;
  setNewEntry: React.Dispatch<React.SetStateAction<NewEntryInput>>;
  busy: boolean;
  authBusy: boolean;
  error: string | null;
  copyNotice: string | null;
  passwordVisible: boolean;
  setPasswordVisible: React.Dispatch<React.SetStateAction<boolean>>;
  authStatus: AuthSessionStatus | null;
  authExpiresText: string | null;
  entryCountText: string;
  handleLock: () => Promise<void>;
  handleAuthSignOut: () => Promise<void>;
  handleCreateEntry: (event: React.FormEvent<HTMLFormElement>) => Promise<void>;
  handleSelectEntry: (id: string) => Promise<void>;
  handleDeleteEntry: (id: string) => Promise<void>;
  handleCopyPassword: () => Promise<void>;
};

export function WorkspaceView({
  entries,
  selectedEntry,
  newEntry,
  setNewEntry,
  busy,
  authBusy,
  error,
  copyNotice,
  passwordVisible,
  setPasswordVisible,
  authStatus,
  authExpiresText,
  entryCountText,
  handleLock,
  handleAuthSignOut,
  handleCreateEntry,
  handleSelectEntry,
  handleDeleteEntry,
  handleCopyPassword,
}: WorkspaceViewProps) {
  return (
    <main className="min-h-screen grid content-start gap-4 p-5">
      {/* Header */}
      <section className="flex items-center justify-between gap-4 flex-wrap">
        <div>
          <h1 className="text-[clamp(1.5rem,3.4vw,2.2rem)] font-semibold tracking-tight m-0">
            etui Desktop
          </h1>
          <p className="text-sm text-slate-500 mt-0.5">{entryCountText}</p>
          {authStatus?.configured ? (
            authStatus.authenticated ? (
              <p className="text-sm text-slate-500 mt-0">
                Sync user: {authStatus.email ?? authStatus.userId ?? "authenticated"}
                {authExpiresText ? ` (${authExpiresText})` : ""}
              </p>
            ) : (
              <p className="text-sm text-slate-500 mt-0">Not signed in to Supabase.</p>
            )
          ) : (
            <p className="text-sm text-slate-500 mt-0">Supabase sync is not configured.</p>
          )}
        </div>
        <div className="flex gap-2 flex-wrap">
          <Button variant="outline" type="button" onClick={handleLock} disabled={busy}>
            Lock
          </Button>
          {authStatus?.configured && authStatus.authenticated ? (
            <Button
              variant="outline"
              type="button"
              onClick={handleAuthSignOut}
              disabled={authBusy}
            >
              {authBusy ? "Signing out..." : "Sign Out"}
            </Button>
          ) : null}
        </div>
      </section>

      {/* Three-panel grid */}
      <section
        className="grid gap-4"
        style={{ gridTemplateColumns: "repeat(auto-fit, minmax(260px, 1fr))" }}
      >
        {/* Create Entry */}
        <Card>
          <CardHeader>
            <CardTitle>Create Entry</CardTitle>
            <CardDescription>Saved encrypted in local SQLite storage.</CardDescription>
          </CardHeader>
          <CardContent>
            <form className="flex flex-col gap-2.5 mt-1" onSubmit={handleCreateEntry}>
              <Label htmlFor="entry-title">Title</Label>
              <Input
                id="entry-title"
                value={newEntry.title}
                onChange={(event) =>
                  setNewEntry((previous) => ({ ...previous, title: event.target.value }))
                }
                required
              />

              <Label htmlFor="entry-username">Username</Label>
              <Input
                id="entry-username"
                value={newEntry.username}
                onChange={(event) =>
                  setNewEntry((previous) => ({ ...previous, username: event.target.value }))
                }
              />

              <Label htmlFor="entry-password">Password</Label>
              <Input
                id="entry-password"
                type="password"
                value={newEntry.password}
                onChange={(event) =>
                  setNewEntry((previous) => ({ ...previous, password: event.target.value }))
                }
                required
              />

              <Label htmlFor="entry-notes">Notes</Label>
              <Textarea
                id="entry-notes"
                value={newEntry.notes}
                onChange={(event) =>
                  setNewEntry((previous) => ({ ...previous, notes: event.target.value }))
                }
                rows={4}
              />

              <Button type="submit" disabled={busy}>
                Add Entry
              </Button>
            </form>

            {error ? <p className="text-red-700 text-sm mt-3">{error}</p> : null}
          </CardContent>
        </Card>

        {/* Entries List */}
        <Card>
          <CardHeader>
            <CardTitle>Entries</CardTitle>
          </CardHeader>
          <CardContent>
            {entries.length === 0 ? (
              <p className="text-sm text-slate-500 mt-2">No entries yet.</p>
            ) : null}
            <ul className="list-none m-0 p-0 flex flex-col gap-2 mt-2">
              {entries.map((entry) => (
                <li key={entry.id} className="flex items-center gap-2">
                  <button
                    type="button"
                    className="flex-1 flex items-center justify-between border border-slate-300 rounded-lg bg-slate-50 text-slate-900 px-2.5 py-2 cursor-pointer gap-2 text-left hover:bg-slate-100 transition-colors disabled:opacity-60 disabled:cursor-not-allowed"
                    onClick={() => handleSelectEntry(entry.id)}
                    disabled={busy}
                  >
                    <span className="flex flex-col">
                      <strong className="text-sm">{entry.title}</strong>
                      <span className="text-xs text-slate-500">
                        {entry.username || "no username"}
                      </span>
                    </span>
                    <span className="text-xs text-slate-500 shrink-0">
                      {new Date(entry.updatedAt).toLocaleString()}
                    </span>
                  </button>
                  <Button
                    variant="destructive"
                    size="sm"
                    type="button"
                    onClick={() => handleDeleteEntry(entry.id)}
                    disabled={busy}
                  >
                    Delete
                  </Button>
                </li>
              ))}
            </ul>
          </CardContent>
        </Card>

        {/* Entry Detail */}
        <Card>
          <CardHeader>
            <CardTitle>Selected Entry</CardTitle>
          </CardHeader>
          <CardContent>
            {selectedEntry ? (
              <div className="flex flex-col gap-2 mt-1">
                <p className="text-sm text-slate-700 mt-0">
                  <strong>Title:</strong> {selectedEntry.title}
                </p>
                <p className="text-sm text-slate-700 mt-0">
                  <strong>Username:</strong> {selectedEntry.username || "-"}
                </p>
                <p className="text-sm text-slate-700 mt-0">
                  <strong>Updated:</strong>{" "}
                  {new Date(selectedEntry.updatedAt).toLocaleString()}
                </p>

                <Label>Password</Label>
                <div className="grid grid-cols-[1fr_auto_auto] gap-2 items-center">
                  <Input
                    type={passwordVisible ? "text" : "password"}
                    readOnly
                    value={selectedEntry.password}
                  />
                  <Button
                    variant="outline"
                    size="sm"
                    type="button"
                    onClick={() => setPasswordVisible((visible) => !visible)}
                  >
                    {passwordVisible ? "Hide" : "Show"}
                  </Button>
                  <Button
                    variant="outline"
                    size="sm"
                    type="button"
                    onClick={handleCopyPassword}
                  >
                    Copy
                  </Button>
                </div>

                {copyNotice ? (
                  <p className="text-slate-700 text-xs mt-0">{copyNotice}</p>
                ) : null}

                <Label>Notes</Label>
                <Textarea rows={5} readOnly value={selectedEntry.notes} />
              </div>
            ) : (
              <p className="text-sm text-slate-500 mt-2">Select an entry to inspect details.</p>
            )}
          </CardContent>
        </Card>
      </section>
    </main>
  );
}
