import React from "react";
import "./SectionContainer.scss";

function SectionContainer({
  as: Component = "div",
  className = "",
  children,
  ...props
}) {
  const classes = ["section-container", className].filter(Boolean).join(" ");

  return (
    <Component className={classes} {...props}>
      {children}
    </Component>
  );
}

export default SectionContainer;
