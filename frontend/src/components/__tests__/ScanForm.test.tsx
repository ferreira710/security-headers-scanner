import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it, vi } from 'vitest';

import { ScanForm } from '../ScanForm';

function setup(busy = false) {
  const onScan = vi.fn();
  render(<ScanForm onScan={onScan} busy={busy} />);
  return { onScan, user: userEvent.setup() };
}

const input = (): HTMLElement => screen.getByLabelText(/endereço do site/i);
const submit = (): HTMLElement => screen.getByRole('button', { name: /analisar headers/i });

describe('ScanForm', () => {
  it('submits the typed URL', async () => {
    const { onScan, user } = setup();
    await user.type(input(), 'example.com');
    await user.click(submit());
    expect(onScan).toHaveBeenCalledWith('example.com');
  });

  it('submits on Enter without needing the button', async () => {
    const { onScan, user } = setup();
    await user.type(input(), 'example.com{Enter}');
    expect(onScan).toHaveBeenCalledWith('example.com');
  });

  it('blocks an empty submission and says why', async () => {
    const { onScan, user } = setup();
    await user.click(submit());
    expect(onScan).not.toHaveBeenCalled();
    expect(screen.getByText(/digite uma url/i)).toBeInTheDocument();
  });

  it.each([
    ['not a url', /espaços/i],
    ['localhost', /domínio completo/i],
    ['ftp://example.com', /http e https/i],
  ])('rejects %s before it ever reaches the API', async (value, expected) => {
    const { onScan, user } = setup();
    await user.type(input(), value);
    await user.click(submit());
    expect(onScan).not.toHaveBeenCalled();
    expect(screen.getByText(expected)).toBeInTheDocument();
  });

  it('links the error to the input for assistive tech', async () => {
    const { user } = setup();
    await user.click(submit());

    expect(input()).toHaveAttribute('aria-invalid', 'true');
    expect(input()).toHaveAccessibleDescription(/digite uma url/i);
  });

  it('clears the error as soon as the user starts fixing it', async () => {
    const { user } = setup();
    await user.click(submit());
    expect(screen.getByText(/digite uma url/i)).toBeInTheDocument();

    await user.type(input(), 'e');
    expect(screen.queryByText(/digite uma url/i)).not.toBeInTheDocument();
    expect(input()).toHaveAttribute('aria-invalid', 'false');
  });

  it('runs an example in one click', async () => {
    const { onScan, user } = setup();
    await user.click(screen.getByRole('button', { name: 'github.com' }));
    expect(onScan).toHaveBeenCalledWith('github.com');
    expect(input()).toHaveValue('github.com');
  });

  it('disables submission while a scan is in flight', () => {
    setup(true);
    expect(screen.getByRole('button', { name: /analisando/i })).toBeDisabled();
  });
});
