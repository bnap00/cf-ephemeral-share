import assert from 'node:assert/strict';
import { getBrandConfig } from '../src/index.js';

const defaults = getBrandConfig();
assert.equal(defaults.name, 'ephemeral');
assert.equal(defaults.logo, '');
assert.equal(defaults.accent, '#1f6feb');

const custom = getBrandConfig({
  BRAND_NAME: '  Acme Share  ',
  BRAND_TAGLINE: '',
  BRAND_FOOTER: 'Internal transfers only.',
  BRAND_LOGO: '/brand/acme.svg?v=2',
  BRAND_ACCENT: '#AABBCC',
  BRAND_ACCENT_DARK: '#123456',
});
assert.deepEqual(custom, {
  name: 'Acme Share',
  tagline: '',
  footer: 'Internal transfers only.',
  logo: '/brand/acme.svg?v=2',
  accent: '#aabbcc',
  accentDark: '#123456',
});

const invalid = getBrandConfig({
  BRAND_NAME: '',
  BRAND_LOGO: 'https://example.com/logo.svg',
  BRAND_ACCENT: 'red',
  BRAND_ACCENT_DARK: '#1234',
});
assert.equal(invalid.name, defaults.name);
assert.equal(invalid.logo, '');
assert.equal(invalid.accent, defaults.accent);
assert.equal(invalid.accentDark, defaults.accentDark);

console.log('branding config passed');
