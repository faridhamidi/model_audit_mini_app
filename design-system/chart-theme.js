/**
 * Chart.js Theme Configuration
 * Observatory Analytics Design System
 */

export const chartTheme = {
  defaults: {
    color: '#6b7a8d',
    borderColor: 'rgba(255, 255, 255, 0.06)',
    font: {
      family: "'Outfit', sans-serif",
      size: 11
    },
    plugins: {
      legend: {
        display: false
      },
      tooltip: {
        backgroundColor: 'rgba(14, 17, 23, 0.95)',
        borderColor: 'rgba(255, 255, 255, 0.1)',
        borderWidth: 1,
        titleFont: {
          family: "'JetBrains Mono', monospace",
          size: 11
        },
        bodyFont: {
          family: "'JetBrains Mono', monospace",
          size: 10
        },
        padding: 10,
        cornerRadius: 6
      }
    }
  }
};

export const chartColors = [
  '#ff6b35', // ember
  '#00d4aa', // cyan
  '#a78bfa', // violet
  '#f472b6', // rose
  '#fbbf24', // gold
  '#38bdf8', // sky
  '#34d399',
  '#fb923c',
  '#c084fc',
  '#f87171'
];

/**
 * Apply theme to Chart.js instance
 */
export function applyChartTheme(Chart) {
  Chart.defaults.color = chartTheme.defaults.color;
  Chart.defaults.borderColor = chartTheme.defaults.borderColor;
  Chart.defaults.font.family = chartTheme.defaults.font.family;
  Chart.defaults.font.size = chartTheme.defaults.font.size;
  Chart.defaults.plugins.legend.display = chartTheme.defaults.plugins.legend.display;
  
  Object.assign(Chart.defaults.plugins.tooltip, chartTheme.defaults.plugins.tooltip);
}
