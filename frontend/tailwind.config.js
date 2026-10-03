/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  darkMode: 'class',
  theme: {
    extend: {
      colors: {
        dark: {
          950: '#000000',
          900: '#060608',
          850: '#0c0c0e',
          800: '#131316',
          750: '#1a1a1f',
          700: '#23232a',
          600: '#32323c',
        },
      },
    },
  },
  plugins: [],
}
