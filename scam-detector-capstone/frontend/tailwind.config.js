/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      fontFamily: {
        sans: ['Inter', 'sans-serif'],
      },
      animation: {
        'pulse-slow': 'pulse 3s cubic-bezier(0.4, 0, 0.6, 1) infinite',
        'glow-red': 'glowRed 2s ease-in-out infinite',
        'glow-yellow': 'glowYellow 2s ease-in-out infinite',
        'glow-green': 'glowGreen 2s ease-in-out infinite',
      },
      keyframes: {
        glowRed: {
          '0%, 100%': { boxShadow: '0 0 15px rgba(239, 68, 68, 0.4)' },
          '50%': { boxShadow: '0 0 40px rgba(239, 68, 68, 0.9)' },
        },
        glowYellow: {
          '0%, 100%': { boxShadow: '0 0 15px rgba(250, 204, 21, 0.4)' },
          '50%': { boxShadow: '0 0 40px rgba(250, 204, 21, 0.9)' },
        },
        glowGreen: {
          '0%, 100%': { boxShadow: '0 0 15px rgba(34, 197, 94, 0.4)' },
          '50%': { boxShadow: '0 0 40px rgba(34, 197, 94, 0.9)' },
        },
      },
    },
  },
  plugins: [],
}
