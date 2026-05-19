import React, { useEffect, useState } from "react";
import "./ThemeToggle.scss";

const THEME_STORAGE_KEY = "traffic-ui-theme";
const THEME_LIGHT = "light";
const THEME_DARK = "dark";

function ThemeToggle() {
  const [theme, setTheme] = useState(() => {
    if (typeof window === "undefined") {
      return THEME_LIGHT;
    }

    return localStorage.getItem(THEME_STORAGE_KEY) || THEME_LIGHT;
  });

  useEffect(() => {
    document.documentElement.setAttribute("data-theme", theme);
    localStorage.setItem(THEME_STORAGE_KEY, theme);
  }, [theme]);

  const isDarkTheme = theme === THEME_DARK;
  const themeLabel = isDarkTheme ? "Light theme" : "Dark theme";

  const handleChange = (event) => {
    setTheme(event.target.checked ? THEME_DARK : THEME_LIGHT);
  };

  return (
    <label className="theme-toggle" title={themeLabel}>
      <input
        type="checkbox"
        role="switch"
        className="theme-toggle__input"
        checked={isDarkTheme}
        onChange={handleChange}
        aria-label={themeLabel}
      />
      <span className="theme-toggle__track" aria-hidden="true">
        <img
          src="/svg/sun.svg"
          alt=""
          className="theme-toggle__icon theme-toggle__icon--sun"
        />
        <img
          src="/svg/moon.svg"
          alt=""
          className="theme-toggle__icon theme-toggle__icon--moon"
        />
        <span className="theme-toggle__thumb" />
      </span>
    </label>
  );
}

export default ThemeToggle;
