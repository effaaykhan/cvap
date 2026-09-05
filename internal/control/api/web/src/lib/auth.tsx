import { createContext, useContext, useEffect, useState, type ReactNode } from "react";
import { api, ApiError, type Session } from "./api";

interface AuthState {
  session: Session | null;
  loading: boolean;
  // mustChange is true when the account must change its password before it may
  // do anything else — the server refuses every other route until it does, so
  // the UI routes straight to the change screen rather than pretending otherwise.
  mustChange: boolean;
  refresh: () => Promise<void>;
  setMustChange: (v: boolean) => void;
  logout: () => Promise<void>;
}

const Ctx = createContext<AuthState | null>(null);

export function AuthProvider({ children }: { children: ReactNode }) {
  const [session, setSession] = useState<Session | null>(null);
  const [loading, setLoading] = useState(true);
  const [mustChange, setMustChange] = useState(false);

  const refresh = async () => {
    try {
      setSession(await api.session());
      setMustChange(false);
    } catch (e) {
      if (e instanceof ApiError && e.status === 401) {
        setSession(null); // no session: sign in
      } else if (e instanceof ApiError && e.status === 403) {
        // The session endpoint has no permission gate, so a 403 on it with a
        // valid cookie can only be the must-change refusal (middleware.go): the
        // account must change its password before it may reach anything else.
        setSession(null);
        setMustChange(true);
      } else {
        throw e;
      }
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    void refresh();
  }, []);

  const logout = async () => {
    try {
      await api.logout();
    } finally {
      setSession(null);
    }
  };

  return (
    <Ctx.Provider value={{ session, loading, mustChange, refresh, setMustChange, logout }}>
      {children}
    </Ctx.Provider>
  );
}

export function useAuth(): AuthState {
  const v = useContext(Ctx);
  if (!v) throw new Error("useAuth outside AuthProvider");
  return v;
}
