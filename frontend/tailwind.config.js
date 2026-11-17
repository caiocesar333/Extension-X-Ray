/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{js,ts,jsx,tsx}'],
  theme: {
    extend: {
      colors: {
        ink: '#070a0f',
        panel: '#0d121a',
        line: '#1d2938',
        cyan: '#42f5d7',
        violet: '#9277ff',
      },
      fontFamily: {
        sans: ['Inter', 'ui-sans-serif', 'system-ui', 'sans-serif'],
        mono: ['JetBrains Mono', 'ui-monospace', 'SFMono-Regular', 'monospace'],
      },
      boxShadow: {
        glow: '0 0 35px rgba(66, 245, 215, .10)',
      },
    },
  },
  plugins: [],
}

