import { config } from 'dotenv';

let configured: boolean = false;

export default function (): boolean {
  if (configured) return false;
  config();
  return (configured = true);
}
