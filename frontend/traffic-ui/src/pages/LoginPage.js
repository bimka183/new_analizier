import React, { useState } from "react";
import { Navigate, useNavigate } from "react-router-dom";
import { useAuth } from "../context/AuthContext";
import Button from "../ui/button";
import "./LoginPage.scss";

function LoginPage() {
  const { login, isAuthenticated } = useAuth();
  const navigate = useNavigate();
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState(null);
  const [submitting, setSubmitting] = useState(false);

  if (isAuthenticated) {
    return <Navigate to="/dashboard" replace />;
  }

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError(null);
    setSubmitting(true);
    try {
      await login({ username, password });
      navigate("/dashboard", { replace: true });
    } catch (err) {
      setError(err instanceof Error ? err.message : "Ошибка входа");
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div className="login-page">
      <div className="login-page__card">
        <h2 className="login-page__title">Вход</h2>
        <p className="login-page__lead">
          Введите учётные данные. Роли в системе: <strong>user</strong> и{" "}
          <strong>admin</strong>. После перезагрузки страницы сессия
          восстанавливается из cookie; пароль хранится только в рамках вкладки
          браузера.
        </p>
        <p className="login-page__hint">
          Локальная разработка: пользователи <code>user</code> / <code>user</code>{" "}
          и <code>admin</code> / <code>admin</code> (как на бэкенде по умолчанию).
        </p>
        <form className="login-page__form" onSubmit={handleSubmit}>
          <label className="login-page__field">
            <span className="login-page__label">Логин</span>
            <input
              className="login-page__input"
              type="text"
              name="username"
              autoComplete="username"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              required
            />
          </label>
          <label className="login-page__field">
            <span className="login-page__label">Пароль</span>
            <input
              className="login-page__input"
              type="password"
              name="password"
              autoComplete="current-password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              required
            />
          </label>
          {error ? (
            <p className="login-page__error" role="alert">
              {error}
            </p>
          ) : null}
          <Button type="submit" disabled={submitting} className="login-page__submit">
            {submitting ? "Вход…" : "Войти"}
          </Button>
        </form>
      </div>
    </div>
  );
}

export default LoginPage;
