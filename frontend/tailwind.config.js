/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{ts,tsx}'],
  theme: {
    extend: {
      boxShadow: {
        glow: '0 0 0 1px rgba(45, 212, 191, 0.12), 0 24px 80px rgba(15, 23, 42, 0.28)',
      },
      colors: {
        midnight: {
          950: '#020617',
          900: '#0f172a',
          850: '#111c35',
        },
        signal: {
          50: '#f0fdfa',
          100: '#ccfbf1',
          400: '#2dd4bf',
          500: '#14b8a6',
          600: '#0d9488',
        },
        ember: {
          400: '#fb923c',
          500: '#f97316',
          600: '#ea580c',
        },
      },
    },
  },
  plugins: [],
};
