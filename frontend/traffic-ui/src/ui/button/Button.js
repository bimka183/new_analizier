import React from "react";
import "./Button.scss";

function Button({
  children,
  icon = null,
  iconPosition = "left",
  className = "",
  type = "button",
  ...buttonProps
}) {
  const classes = ["ui-button", className].filter(Boolean).join(" ");
  const iconNode = icon ? <span className="ui-button__icon">{icon}</span> : null;

  return (
    <button type={type} className={classes} {...buttonProps}>
      {iconPosition === "left" && iconNode}
      <span className="ui-button__label">{children}</span>
      {iconPosition === "right" && iconNode}
    </button>
  );
}

export default Button;
