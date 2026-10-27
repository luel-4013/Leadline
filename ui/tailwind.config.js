/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        void: {
          DEFAULT: 'rgb(var(--color-bg-rgb) / <alpha-value>)',
          800: 'rgb(var(--color-bg-panel-rgb) / <alpha-value>)',
          700: 'rgb(var(--color-bg-elevated-rgb) / <alpha-value>)',
        },
        signal: {
          DEFAULT: 'rgb(var(--color-accent-rgb) / <alpha-value>)',
          dim: 'rgb(var(--color-accent-dim-rgb) / <alpha-value>)',
        },
      },
      fontFamily: {
        mono: ['"JetBrains Mono"', '"Fira Code"', 'ui-monospace', 'monospace'],
        display: ['var(--font-display)', 'Inter', 'ui-sans-serif', 'sans-serif'],
      },
      boxShadow: {
        glow: '0 0 0 1px var(--color-accent-a15), 0 0 24px -4px var(--color-accent-a25)',
      },
    },
  },
  plugins: [],
}
