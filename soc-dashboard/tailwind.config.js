/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{js,jsx}'],
  theme: {
    extend: {
      colors: {
        canvas: '#1C3B2B',
        surface: {
          0: '#F8FAF8',
          1: '#FFFFFF',
          2: '#F0F5F2',
          3: '#E2ECE6',
          4: '#D4E2DA',
        },
        forest: {
          DEFAULT: '#0B4F30',
          dark: '#073620',
          hover: '#14532D',
          light: '#E8F5EE',
          border: '#A3D9BC',
        },
        mint: {
          DEFAULT: '#10B981',
          light: '#D1FAE5',
          secondary: '#7FC8A9',
        },
        border: {
          DEFAULT: '#E1E8E3',
          strong: '#C2D3C8',
        },
        ink: {
          primary: '#1A2E23',
          secondary: '#496052',
          muted: '#7A9183',
          light: '#9EAF9B',
        },
        accent: {
          DEFAULT: '#0B4F30',
          hover: '#14532D',
          dim: 'rgba(11, 79, 48, 0.08)',
        },
        badge: {
          teal: '#0D9488',
          tealBg: '#CCFBF1',
          orange: '#EA580C',
          orangeBg: '#FFEDD5',
          purple: '#7C3AED',
          purpleBg: '#EDE9FE',
          blue: '#0284C7',
          blueBg: '#E0F2FE',
        },
        signal: {
          DEFAULT: '#10B981',
          dim: 'rgba(16, 185, 129, 0.12)',
        },
        sev: {
          critical: '#DC2626',
          criticalBg: 'rgba(220, 38, 38, 0.08)',
          criticalBorder: 'rgba(220, 38, 38, 0.25)',
          high: '#EA580C',
          highBg: 'rgba(234, 88, 12, 0.08)',
          highBorder: 'rgba(234, 88, 12, 0.25)',
          medium: '#D97706',
          mediumBg: 'rgba(217, 119, 6, 0.08)',
          mediumBorder: 'rgba(217, 119, 6, 0.2)',
          low: '#0284C7',
          lowBg: 'rgba(2, 132, 199, 0.08)',
          lowBorder: 'rgba(2, 132, 199, 0.2)',
        },
      },
      fontFamily: {
        sans: ['"Inter"', '"Poppins"', 'ui-sans-serif', 'system-ui', 'sans-serif'],
        mono: ['"JetBrains Mono"', '"IBM Plex Mono"', 'ui-monospace', 'monospace'],
      },
      fontSize: {
        '2xs': ['10px', '14px'],
      },
      borderRadius: {
        'xl': '16px',
        '2xl': '20px',
        '3xl': '24px',
      },
      boxShadow: {
        card: '0 2px 8px -2px rgba(11, 79, 48, 0.06), 0 1px 3px rgba(0, 0, 0, 0.04)',
        elevated: '0 10px 30px -5px rgba(11, 79, 48, 0.12), 0 4px 6px -2px rgba(0, 0, 0, 0.04)',
        modal: '0 20px 50px -10px rgba(7, 54, 32, 0.25)',
        floating: '0 12px 40px rgba(0, 0, 0, 0.15)',
      },
      keyframes: {
        pulseDot: {
          '0%, 100%': { opacity: 1 },
          '50%': { opacity: 0.3 },
        },
        slideIn: {
          from: { opacity: 0, transform: 'translateY(-4px)' },
          to: { opacity: 1, transform: 'translateY(0)' },
        },
        fadeUp: {
          from: { opacity: 0, transform: 'translateY(8px)' },
          to: { opacity: 1, transform: 'translateY(0)' },
        },
        travel: {
          '0%': { transform: 'translateX(0)', opacity: 0 },
          '15%': { opacity: 1 },
          '85%': { opacity: 1 },
          '100%': { transform: 'translateX(calc(100% - 6px))', opacity: 0 },
        },
      },
      animation: {
        pulseDot: 'pulseDot 2s ease-in-out infinite',
        slideIn: 'slideIn 0.18s ease-out',
        fadeUp: 'fadeUp 0.25s ease-out',
        travel: 'travel 2.4s linear infinite',
      },
    },
  },
  plugins: [],
}
