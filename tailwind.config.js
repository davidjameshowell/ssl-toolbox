/** Tailwind build config — compiles css/app.css to assets/app.css.
 *  Run `npm run build:css` after changing markup classes or component styles.
 *  The compiled file is committed; there is no runtime CSS compilation. */
export default {
    darkMode: 'class',
    content: ['./index.html', './js/**/*.js'],
    safelist: [
        // Toggled from JS only (passwordGroup fade-in), never present in scanned markup.
        'opacity-100',
    ],
    theme: {
        extend: {
            fontFamily: {
                sans: ['Inter', 'ui-sans-serif', 'system-ui', '-apple-system', 'Segoe UI', 'Roboto', 'Helvetica Neue', 'Arial', 'sans-serif'],
                mono: ['ui-monospace', 'SFMono-Regular', 'Menlo', 'Consolas', 'Liberation Mono', 'monospace'],
            },
            boxShadow: {
                card: '0 1px 2px rgba(15, 23, 42, 0.06)',
            },
        },
    },
    plugins: [],
};
