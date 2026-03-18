import React, { useEffect, useMemo, useRef, useState } from "react";
import { createRoot } from "react-dom/client";
import { invoke } from "@tauri-apps/api/core";
import "./styles.css";

type SessionInfo = {
  vaultId: string;
  entryCount: number;
};

type EntrySummary = {
  id: string;
  title: string;
  username: string;
  updatedAt: string;
};

type EntryDetail = {
  id: string;
  title: string;
  username: string;
  password: string;
  notes: string;
  updatedAt: string;
};

type NewEntryInput = {
  title: string;
  username: string;
  password: string;
  notes: string;
};

const EMPTY_ENTRY: NewEntryInput = {
  title: "",
  username: "",
  password: "",
  notes: "",
};

const CLIPBOARD_CLEAR_MS = 30_000;

function App() {
  const [masterPassword, setMasterPassword] = useState("");
  const [session, setSession] = useState<SessionInfo | null>(null);
  const [entries, setEntries] = useState<EntrySummary[]>([]);
  const [selectedEntry, setSelectedEntry] = useState<EntryDetail | null>(null);
  const [newEntry, setNewEntry] = useState<NewEntryInput>(EMPTY_ENTRY);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [copyNotice, setCopyNotice] = useState<string | null>(null);
  const clipboardClearTimer = useRef<number | null>(null);

  function clearClipboardTimer() {
    if (clipboardClearTimer.current !== null) {
      window.clearTimeout(clipboardClearTimer.current);
      clipboardClearTimer.current = null;
    }
  }

  function resetSessionState(nextError: string | null = null) {
    setSession(null);
    setEntries([]);
    setSelectedEntry(null);
    setNewEntry(EMPTY_ENTRY);
    setMasterPassword("");
    setCopyNotice(null);
    clearClipboardTimer();
    setError(nextError);
  }

  function handleCommandError(operationError: unknown) {
    const message = String(operationError);
    if (message.includes("vault is locked")) {
      resetSessionState("Session timed out. Unlock again.");
      return;
    }
    setError(message);
  }

  useEffect(() => {
    return () => {
      clearClipboardTimer();
    };
  }, []);

  const entryCountText = useMemo(() => {
    if (!session) {
      return "";
    }
    return `${entries.length} entries loaded`;
  }, [entries.length, session]);

  async function refreshEntries() {
    const nextEntries = await invoke<EntrySummary[]>("list_entries");
    setEntries(nextEntries);
    if (nextEntries.length === 0) {
      setSelectedEntry(null);
    }
  }

  async function handleUnlock(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setBusy(true);
    setError(null);

    try {
      const unlocked = await invoke<SessionInfo>("unlock_vault", { masterPassword });
      setSession(unlocked);
      setMasterPassword("");
      setCopyNotice(null);
      await refreshEntries();
    } catch (unlockError) {
      handleCommandError(unlockError);
    } finally {
      setBusy(false);
    }
  }

  async function handleLock() {
    setBusy(true);
    setError(null);

    try {
      await invoke("lock_vault");
      resetSessionState(null);
    } catch (lockError) {
      handleCommandError(lockError);
    } finally {
      setBusy(false);
    }
  }

  async function handleCreateEntry(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setBusy(true);
    setError(null);

    try {
      await invoke<EntryDetail>("create_entry", { input: newEntry });
      setNewEntry(EMPTY_ENTRY);
      await refreshEntries();
    } catch (createError) {
      handleCommandError(createError);
    } finally {
      setBusy(false);
    }
  }

  async function handleSelectEntry(entryId: string) {
    setBusy(true);
    setError(null);

    try {
      const detail = await invoke<EntryDetail | null>("get_entry", { entryId });
      setSelectedEntry(detail);
      setCopyNotice(null);
    } catch (loadError) {
      handleCommandError(loadError);
    } finally {
      setBusy(false);
    }
  }

  async function handleDeleteEntry(entryId: string) {
    setBusy(true);
    setError(null);

    try {
      await invoke("delete_entry", { entryId });
      if (selectedEntry?.id === entryId) {
        setSelectedEntry(null);
      }
      await refreshEntries();
    } catch (deleteError) {
      handleCommandError(deleteError);
    } finally {
      setBusy(false);
    }
  }

  async function handleCopyPassword() {
    if (!selectedEntry) {
      return;
    }

    setError(null);
    try {
      await navigator.clipboard.writeText(selectedEntry.password);
      setCopyNotice("Password copied. Clipboard will be cleared in 30 seconds.");
      clearClipboardTimer();

      const copiedPassword = selectedEntry.password;
      clipboardClearTimer.current = window.setTimeout(() => {
        void clearClipboardIfUnchanged(copiedPassword);
      }, CLIPBOARD_CLEAR_MS);
    } catch (copyError) {
      handleCommandError(copyError);
    }
  }

  async function clearClipboardIfUnchanged(copiedPassword: string) {
    let shouldClear = true;
    try {
      const currentClipboard = await navigator.clipboard.readText();
      shouldClear = currentClipboard === copiedPassword;
    } catch {
      shouldClear = true;
    }

    if (!shouldClear) {
      setCopyNotice(null);
      return;
    }

    try {
      await navigator.clipboard.writeText("");
    } finally {
      setCopyNotice(null);
    }
  }

  if (!session) {
    return (
      <main className="unlock-shell">
        <form className="panel" onSubmit={handleUnlock}>
          <h1>Vault Desktop</h1>
          <p>Unlock your local encrypted vault.</p>

          <label className="field-label" htmlFor="master-password">
            Master password
          </label>
          <input
            id="master-password"
            className="text-input"
            type="password"
            value={masterPassword}
            onChange={(event) => setMasterPassword(event.target.value)}
            autoComplete="current-password"
            placeholder="Enter master password"
            required
          />

          <button className="primary-btn" type="submit" disabled={busy}>
            {busy ? "Unlocking..." : "Unlock"}
          </button>
          {error ? <p className="error-text">{error}</p> : null}
        </form>
      </main>
    );
  }

  return (
    <main className="workspace-shell">
      <section className="workspace-header">
        <div>
          <h1>Vault Desktop</h1>
          <p>{entryCountText}</p>
        </div>
        <button className="ghost-btn" type="button" onClick={handleLock} disabled={busy}>
          Lock
        </button>
      </section>

      <section className="workspace-grid">
        <article className="panel">
          <h2>Create Entry</h2>
          <p>Saved encrypted in local SQLite storage.</p>

          <form className="stack-form" onSubmit={handleCreateEntry}>
            <label className="field-label" htmlFor="entry-title">
              Title
            </label>
            <input
              id="entry-title"
              className="text-input"
              value={newEntry.title}
              onChange={(event) =>
                setNewEntry((previous) => ({ ...previous, title: event.target.value }))
              }
              required
            />

            <label className="field-label" htmlFor="entry-username">
              Username
            </label>
            <input
              id="entry-username"
              className="text-input"
              value={newEntry.username}
              onChange={(event) =>
                setNewEntry((previous) => ({ ...previous, username: event.target.value }))
              }
            />

            <label className="field-label" htmlFor="entry-password">
              Password
            </label>
            <input
              id="entry-password"
              className="text-input"
              type="password"
              value={newEntry.password}
              onChange={(event) =>
                setNewEntry((previous) => ({ ...previous, password: event.target.value }))
              }
              required
            />

            <label className="field-label" htmlFor="entry-notes">
              Notes
            </label>
            <textarea
              id="entry-notes"
              className="text-area"
              value={newEntry.notes}
              onChange={(event) =>
                setNewEntry((previous) => ({ ...previous, notes: event.target.value }))
              }
              rows={4}
            />

            <button className="primary-btn" type="submit" disabled={busy}>
              Add Entry
            </button>
          </form>

          {error ? <p className="error-text">{error}</p> : null}
        </article>

        <article className="panel">
          <h2>Entries</h2>
          {entries.length === 0 ? <p>No entries yet.</p> : null}
          <ul className="entry-list">
            {entries.map((entry) => (
              <li key={entry.id} className="entry-item">
                <button
                  className="entry-select"
                  type="button"
                  onClick={() => handleSelectEntry(entry.id)}
                  disabled={busy}
                >
                  <span>
                    <strong>{entry.title}</strong>
                    <span className="entry-meta">{entry.username || "no username"}</span>
                  </span>
                  <span className="entry-meta">{new Date(entry.updatedAt).toLocaleString()}</span>
                </button>
                <button
                  className="danger-btn"
                  type="button"
                  onClick={() => handleDeleteEntry(entry.id)}
                  disabled={busy}
                >
                  Delete
                </button>
              </li>
            ))}
          </ul>
        </article>

        <article className="panel">
          <h2>Selected Entry</h2>
          {selectedEntry ? (
            <div className="entry-detail">
              <p>
                <strong>Title:</strong> {selectedEntry.title}
              </p>
              <p>
                <strong>Username:</strong> {selectedEntry.username || "-"}
              </p>
              <p>
                <strong>Updated:</strong> {new Date(selectedEntry.updatedAt).toLocaleString()}
              </p>
              <label className="field-label">Password</label>
              <div className="password-row">
                <input className="text-input" type="password" readOnly value={selectedEntry.password} />
                <button className="ghost-btn" type="button" onClick={handleCopyPassword}>
                  Copy
                </button>
              </div>
              {copyNotice ? <p className="info-text">{copyNotice}</p> : null}
              <label className="field-label">Notes</label>
              <textarea className="text-area" rows={5} readOnly value={selectedEntry.notes} />
            </div>
          ) : (
            <p>Select an entry to inspect details.</p>
          )}
        </article>
      </section>
    </main>
  );
}

createRoot(document.getElementById("root")!).render(
  <React.StrictMode>
    <App />
  </React.StrictMode>,
);
