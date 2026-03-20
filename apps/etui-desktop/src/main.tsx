import React, { useEffect, useMemo, useState } from "react";
import { createRoot } from "react-dom/client";
import { invoke } from "@tauri-apps/api/core";
import "./index.css";
import { UnlockScreen } from "@/components/UnlockScreen";
import { WorkspaceView } from "@/components/WorkspaceView";
import type { AuthSessionStatus, EntrySummary, EntryDetail, NewEntryInput, SessionInfo } from "@/types";

const EMPTY_ENTRY: NewEntryInput = {
  title: "",
  username: "",
  password: "",
  notes: "",
};

function App() {
  const [masterPassword, setMasterPassword] = useState("");
  const [session, setSession] = useState<SessionInfo | null>(null);
  const [entries, setEntries] = useState<EntrySummary[]>([]);
  const [selectedEntry, setSelectedEntry] = useState<EntryDetail | null>(null);
  const [newEntry, setNewEntry] = useState<NewEntryInput>(EMPTY_ENTRY);
  const [busy, setBusy] = useState(false);
  const [authBusy, setAuthBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [copyNotice, setCopyNotice] = useState<string | null>(null);
  const [passwordVisible, setPasswordVisible] = useState(false);
  const [authStatus, setAuthStatus] = useState<AuthSessionStatus | null>(null);
  const [authEmail, setAuthEmail] = useState("");
  const [authPassword, setAuthPassword] = useState("");

  function resetSessionState(nextError: string | null = null) {
    setSession(null);
    setEntries([]);
    setSelectedEntry(null);
    setNewEntry(EMPTY_ENTRY);
    setMasterPassword("");
    setCopyNotice(null);
    setPasswordVisible(false);
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
    void invoke<AuthSessionStatus>("auth_session_status")
      .then((status) => {
        setAuthStatus(status);
      })
      .catch((statusError) => {
        setError(String(statusError));
      });
  }, []);

  const entryCountText = useMemo(() => {
    if (!session) {
      return "";
    }
    return `${entries.length} entries loaded`;
  }, [entries.length, session]);

  const authExpiresText = useMemo(() => {
    if (!authStatus?.authenticated || authStatus.expiresInSeconds === null) {
      return null;
    }

    const wholeMinutes = Math.floor(authStatus.expiresInSeconds / 60);
    if (wholeMinutes < 1) {
      return "expires in under 1 minute";
    }

    return `expires in about ${wholeMinutes} minute${wholeMinutes === 1 ? "" : "s"}`;
  }, [authStatus]);

  const canUnlockVault = !authStatus?.configured || authStatus.authenticated;

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

  async function handleAuthSignIn(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setAuthBusy(true);
    setError(null);

    try {
      const status = await invoke<AuthSessionStatus>("auth_sign_in", {
        email: authEmail,
        password: authPassword,
      });
      setAuthStatus(status);
      setAuthPassword("");
    } catch (signInError) {
      handleCommandError(signInError);
    } finally {
      setAuthBusy(false);
    }
  }

  async function handleAuthSignOut() {
    setAuthBusy(true);
    setError(null);

    try {
      const status = await invoke<AuthSessionStatus>("auth_sign_out");
      setAuthStatus(status);
      setAuthPassword("");
    } catch (signOutError) {
      handleCommandError(signOutError);
    } finally {
      setAuthBusy(false);
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
      setPasswordVisible(false);
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
      setCopyNotice("Password copied.");
    } catch (copyError) {
      handleCommandError(copyError);
    }
  }

  if (!session) {
    return (
      <UnlockScreen
        authStatus={authStatus}
        authExpiresText={authExpiresText}
        canUnlockVault={canUnlockVault}
        authEmail={authEmail}
        setAuthEmail={setAuthEmail}
        authPassword={authPassword}
        setAuthPassword={setAuthPassword}
        masterPassword={masterPassword}
        setMasterPassword={setMasterPassword}
        busy={busy}
        authBusy={authBusy}
        error={error}
        handleAuthSignIn={handleAuthSignIn}
        handleAuthSignOut={handleAuthSignOut}
        handleUnlock={handleUnlock}
      />
    );
  }

  return (
    <WorkspaceView
      entries={entries}
      selectedEntry={selectedEntry}
      newEntry={newEntry}
      setNewEntry={setNewEntry}
      busy={busy}
      authBusy={authBusy}
      error={error}
      copyNotice={copyNotice}
      passwordVisible={passwordVisible}
      setPasswordVisible={setPasswordVisible}
      authStatus={authStatus}
      authExpiresText={authExpiresText}
      entryCountText={entryCountText}
      handleLock={handleLock}
      handleAuthSignOut={handleAuthSignOut}
      handleCreateEntry={handleCreateEntry}
      handleSelectEntry={handleSelectEntry}
      handleDeleteEntry={handleDeleteEntry}
      handleCopyPassword={handleCopyPassword}
    />
  );
}

createRoot(document.getElementById("root")!).render(
  <React.StrictMode>
    <App />
  </React.StrictMode>,
);
