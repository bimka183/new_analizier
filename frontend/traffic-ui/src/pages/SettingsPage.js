import React, { useCallback, useState } from "react";
import { Link } from "react-router-dom";
import { deleteAllTraffic, resetDatabase } from "../api/adminApi";
import { useAuth } from "../context/AuthContext";
import { getAdminAuthorizationHeader } from "../auth/sessionPersistence";
import Button from "../ui/button";
import "./SettingsPage.scss";

function SettingsPage({ onAfterAdminMutation }) {
  const { isAuthenticated, user } = useAuth();
  const [message, setMessage] = useState(null);
  const [error, setError] = useState(null);
  const [busyKey, setBusyKey] = useState(null);

  const hasAdminHeader = Boolean(getAdminAuthorizationHeader());
  const isAdmin = user?.role === "admin";
  const canUseAdminApi = isAuthenticated && isAdmin && hasAdminHeader;

  const runMutation = useCallback(
    async (key, fn, confirmText) => {
      if (!canUseAdminApi) return;
      if (!window.confirm(confirmText)) return;
      setError(null);
      setMessage(null);
      setBusyKey(key);
      try {
        const result = await fn();
        setMessage(
          typeof result.status === "string"
            ? result.status
            : "Операция выполнена."
        );
        if (typeof onAfterAdminMutation === "function") {
          await onAfterAdminMutation();
        }
      } catch (e) {
        setError(e instanceof Error ? e.message : "Неизвестная ошибка");
      } finally {
        setBusyKey(null);
      }
    },
    [canUseAdminApi, onAfterAdminMutation]
  );

  const handleDeleteTraffic = useCallback(() => {
    runMutation(
      "traffic",
      deleteAllTraffic,
      "Удалить все данные трафика? Это действие нельзя отменить."
    );
  }, [runMutation]);

  const handleResetDb = useCallback(() => {
    runMutation(
      "reset",
      resetDatabase,
      "Сбросить базу данных к состоянию по умолчанию? Будут затронуты все связанные данные. Продолжить?"
    );
  }, [runMutation]);

  return (
    <div className="settings-page">
      <h2 className="settings-page__title">Настройки</h2>
      <p className="settings-page__lead">
        Опасные операции администратора. Доступны только роли{" "}
        <strong>admin</strong> с действующим паролем в этой вкладке браузера.
      </p>

      {!isAuthenticated ? (
        <p className="settings-page__notice">
          <Link to="/login">Войдите</Link>, чтобы продолжить.
        </p>
      ) : null}

      {isAuthenticated && !isAdmin ? (
        <p className="settings-page__notice" role="status">
          У вашей учётной записи нет прав администратора.
        </p>
      ) : null}

      {isAuthenticated && isAdmin && !hasAdminHeader ? (
        <p className="settings-page__notice" role="status">
          Сессия без пароля (например, после перезагрузки страницы).{" "}
          <Link to="/login">Войдите снова</Link>, чтобы вызывать админ-API.
        </p>
      ) : null}

      {canUseAdminApi ? (
        <div className="settings-page__actions">
          <section className="settings-page__card" aria-labelledby="settings-delete-traffic">
            <h3 id="settings-delete-traffic" className="settings-page__card-title">
              Удалить весь трафик
            </h3>
            <p className="settings-page__card-desc">
              <code>DELETE /api/admin/traffic</code> — удаляет все записи трафика
              из базы.
            </p>
            <Button
              type="button"
              disabled={busyKey !== null}
              className="settings-page__btn settings-page__btn--danger"
              onClick={handleDeleteTraffic}
            >
              {busyKey === "traffic" ? "Выполняется…" : "Удалить все данные трафика"}
            </Button>
          </section>

          <section className="settings-page__card" aria-labelledby="settings-reset-db">
            <h3 id="settings-reset-db" className="settings-page__card-title">
              Сброс базы данных
            </h3>
            <p className="settings-page__card-desc">
              <code>POST /api/admin/reset</code> — откат базы к дефолтному
              состоянию на стороне сервера.
            </p>
            <Button
              type="button"
              disabled={busyKey !== null}
              className="settings-page__btn settings-page__btn--danger"
              onClick={handleResetDb}
            >
              {busyKey === "reset" ? "Выполняется…" : "Сбросить БД"}
            </Button>
          </section>
        </div>
      ) : null}

      {message ? (
        <p className="settings-page__success" role="status">
          {message}
        </p>
      ) : null}
      {error ? (
        <p className="settings-page__error" role="alert">
          {error}
        </p>
      ) : null}
    </div>
  );
}

export default SettingsPage;
