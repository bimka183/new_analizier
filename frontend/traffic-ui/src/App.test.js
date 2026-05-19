import { render, screen } from "@testing-library/react";
import { MemoryRouter } from "react-router";
import App from "./App";
import { AuthProvider } from "./context/AuthContext";

test("renders main heading", () => {
  render(
    <MemoryRouter initialEntries={["/analyze-file"]}>
      <AuthProvider>
        <App />
      </AuthProvider>
    </MemoryRouter>
  );
  expect(screen.getByRole("heading", { name: /network traffic/i })).toBeInTheDocument();
});
