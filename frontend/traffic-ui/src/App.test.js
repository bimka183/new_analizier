import { render, screen } from '@testing-library/react';
import App from './App';

test('renders main heading', () => {
  render(<App />);
  expect(screen.getByRole('heading', { name: /network traffic/i })).toBeInTheDocument();
});
