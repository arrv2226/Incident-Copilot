import React, { useCallback, useEffect, useMemo, useState } from "react";

function useAuthState() {
  const parseStoredUser = () => {
    const raw = localStorage.getItem("copilot_user");
    if (!raw) return null;
    try {
      return JSON.parse(raw);
    } catch {
      localStorage.removeItem("copilot_user");
      return null;
    }
  };

  const [token, setToken] = useState(localStorage.getItem("copilot_token") || "");
  const [user, setUser] = useState(parseStoredUser);

  const save = (nextToken, nextUser) => {
    localStorage.setItem("copilot_token", nextToken);
    localStorage.setItem("copilot_user", JSON.stringify(nextUser));
    setToken(nextToken);
    setUser(nextUser);
  };

  const clear = () => {
    localStorage.removeItem("copilot_token");
    localStorage.removeItem("copilot_user");
    setToken("");
    setUser(null);
  };

  return { token, user, save, clear };
}

export default function App() {
  const auth = useAuthState();
  const authed = Boolean(auth.token && auth.user);

  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [authMsg, setAuthMsg] = useState("");

  const [sessions, setSessions] = useState([]);
  const [activeChatId, setActiveChatId] = useState(null);
  const [messages, setMessages] = useState([]);
  const [input, setInput] = useState("");
  const [sending, setSending] = useState(false);

  const headers = useMemo(() => ({ Authorization: `Bearer ${auth.token}` }), [auth.token]);

  const apiJson = useCallback(async (url, options = {}) => {
    const res = await fetch(url, options);
    const data = await res.json().catch(() => ({}));
    if (!res.ok) {
      throw new Error(data.detail || data.error || "Request failed");
    }
    return data;
  }, []);

  const loadSessions = useCallback(async () => {
    if (!authed) return;
    const data = await apiJson("/api/chat/sessions", { headers });
    setSessions(data.sessions || []);
  }, [apiJson, authed, headers]);

  const loadChat = useCallback(async (chatId) => {
    const data = await apiJson(`/api/chat/sessions/${chatId}`, { headers });
    setActiveChatId(chatId);
    setMessages((data.messages || []).map((m) => ({ role: m.role === "user" ? "user" : "assistant", content: m.content })));
  }, [apiJson, headers]);

  async function authSubmit(mode) {
    setAuthMsg("");
    try {
      const data = await apiJson(`/api/auth/${mode}`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username: username.trim(), password: password.trim() }),
      });
      auth.save(data.token, data.user);
      setPassword("");
    } catch (err) {
      setAuthMsg(err.message || "Auth failed");
    }
  }

  async function sendMessage() {
    const text = input.trim();
    if (!text || sending) return;
    setSending(true);
    setInput("");
    setMessages((prev) => [...prev, { role: "user", content: text }]);
    try {
      const data = await apiJson("/api/chat", {
        method: "POST",
        headers: { "Content-Type": "application/json", ...headers },
        body: JSON.stringify({
          chat_id: activeChatId,
          message: text,
          approved_by: auth.user?.username || "chat_user",
          retrieval_mode: "vector",
        }),
      });
      setActiveChatId(data.chat_id || activeChatId);
      setMessages((prev) => [...prev, { role: "assistant", content: data.assistant || "No response." }]);
      await loadSessions();
    } catch (err) {
      setMessages((prev) => [...prev, { role: "assistant", content: `Error: ${err.message}` }]);
    } finally {
      setSending(false);
    }
  }

  useEffect(() => {
    if (authed) {
      loadSessions().catch(() => auth.clear());
    }
  }, [authed, loadSessions]);

  if (!authed) {
    return (
      <div className="auth-screen">
        <div className="auth-card">
          <h1>Incident Copilot</h1>
          <p>Sign in to continue</p>
          <input value={username} onChange={(e) => setUsername(e.target.value)} autoComplete="username" placeholder="Username" />
          <input value={password} onChange={(e) => setPassword(e.target.value)} autoComplete="current-password" type="password" placeholder="Password" />
          <div className="auth-actions">
            <button onClick={() => authSubmit("login")}>Login</button>
            <button className="ghost" onClick={() => authSubmit("register")}>Register</button>
          </div>
          <p className="muted">{authMsg}</p>
        </div>
      </div>
    );
  }

  return (
    <div className="app-shell">
      <aside className="sidebar">
        <div className="brand">IncidentGPT</div>
        <button onClick={() => { setActiveChatId(null); setMessages([]); }} className="new-chat">+ New chat</button>
        <div className="history-title">Recents</div>
        <div className="history-list">
          {sessions.map((s) => (
            <button key={s.chat_id} className={`history-item ${activeChatId === s.chat_id ? "active" : ""}`} onClick={() => loadChat(s.chat_id)}>
              {s.title || s.chat_id}
            </button>
          ))}
        </div>
        <div className="sidebar-footer">
          <div className="user-badge">{auth.user.username}</div>
          <button className="ghost" onClick={auth.clear}>Logout</button>
        </div>
      </aside>

      <main className="chat-main">
        <header className="chat-header">
          <div className="chat-title">AI Incident Copilot</div>
          <div className="chat-tabs"><span className="tab active">Chat</span></div>
        </header>
        {messages.length === 0 && (
          <section className="empty-state">
            <h2>What's on the agenda today?</h2>
            <p>Share incident details and I will investigate, draft a remedy, and ask for approval.</p>
          </section>
        )}
        <section className="chat-messages">
          <div className="chat-stream">
            {messages.map((m, i) => (
              <div key={`${m.role}-${i}`} className={`msg-row ${m.role}`}>
                <div className={`msg ${m.role}`}>{m.content}</div>
              </div>
            ))}
          </div>
        </section>
        <footer className="chat-input-wrap">
          <input
            value={input}
            onChange={(e) => setInput(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === "Enter") {
                e.preventDefault();
                sendMessage();
              }
            }}
            placeholder="Ask anything, or paste incident/alert details..."
          />
          <button onClick={sendMessage} disabled={sending}>{sending ? "..." : "Send"}</button>
        </footer>
      </main>
    </div>
  );
}
