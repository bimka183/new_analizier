import React, { useEffect, useState } from "react";
import Button from "../button";
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
  const themeIconPath = isDarkTheme ? "/svg/sun.svg" : "/svg/moon.svg";
  const themeLabel = isDarkTheme ? "Light theme" : "Dark theme";

  const handleThemeToggle = () => {
    setTheme((currentTheme) =>
      currentTheme === THEME_DARK ? THEME_LIGHT : THEME_DARK,
    );
  };

  return (
    <Button
      className="theme-toggle"
      onClick={handleThemeToggle}
      aria-label={themeLabel}
      title={themeLabel}
      icon={
        <img
          src={themeIconPath}
          alt=""
          className="theme-toggle__icon"
          aria-hidden="true"
        />
      }
    >
      {themeLabel}
    </Button>
  );
}

export default ThemeToggle;
