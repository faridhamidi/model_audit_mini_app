# Observatory Analytics Design System

A modern, dark-themed design system for analytics dashboards and data visualization interfaces.

## Features

- **Dark Theme** - Sophisticated dark color palette with ambient glow effects
- **Typography Scale** - Display, body, and monospace font families
- **Component Library** - Buttons, cards, tables, charts, and layouts
- **Animation System** - GSAP-powered entrance and interaction animations
- **Chart Theming** - Pre-configured Chart.js theme
- **Responsive** - Mobile-first responsive grid system

## Installation

### CSS Only

```html
<link rel="preconnect" href="https://fonts.googleapis.com"/>
<link href="https://fonts.googleapis.com/css2?family=DM+Serif+Display&family=JetBrains+Mono:wght@400;600&family=Outfit:wght@300;400;600;800&display=swap" rel="stylesheet"/>
<link rel="stylesheet" href="design-system/index.css"/>
```

### With JavaScript (Charts & Animations)

```html
<!-- Chart.js -->
<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.7/dist/chart.umd.min.js"></script>
<!-- GSAP -->
<script src="https://cdn.jsdelivr.net/npm/gsap@3.12.7/dist/gsap.min.js"></script>

<!-- Design System -->
<link rel="stylesheet" href="design-system/index.css"/>
<script type="module">
  import { applyChartTheme } from './design-system/chart-theme.js';
  import { entranceAnimation } from './design-system/animations.js';
  
  applyChartTheme(Chart);
  entranceAnimation();
</script>
```

## Design Tokens

### Colors

```css
--void: #08090c;        /* Background */
--surface: #0e1117;     /* Card background */
--raised: #161b24;      /* Elevated elements */
--glass: rgba(255, 255, 255, 0.04);  /* Glassmorphism */

--text: #e8edf5;        /* Primary text */
--text-dim: #6b7a8d;    /* Secondary text */
--text-muted: #3d4a5c;  /* Tertiary text */

--ember: #ff6b35;       /* Primary brand */
--cyan: #00d4aa;        /* Success/Active */
--violet: #a78bfa;      /* Accent */
--rose: #f472b6;        /* Error/Warning */
--gold: #fbbf24;        /* Highlight */
--sky: #38bdf8;         /* Info */
```

### Typography

```css
--font-display: 'DM Serif Display', serif;
--font-body: 'Outfit', sans-serif;
--font-mono: 'JetBrains Mono', monospace;
```

### Spacing

```css
--space-xs: 4px;
--space-sm: 8px;
--space-md: 12px;
--space-lg: 16px;
--space-xl: 24px;
--space-2xl: 28px;
--space-3xl: 40px;
```

## Components

### Buttons

```html
<button class="btn">Default</button>
<button class="btn primary">Primary</button>
<button class="btn active">Active</button>
<button class="btn" disabled>Disabled</button>
```

### KPI Cards

```html
<article class="kpi">
  <div class="label">Total Events</div>
  <div class="value text-cyan">1,234</div>
</article>
```

### Panels

```html
<article class="panel">
  <h2>Chart Title <span class="al"></span></h2>
  <div class="chart-box">
    <canvas id="myChart"></canvas>
  </div>
</article>
```

### Tables

```html
<div class="table-wrap">
  <table>
    <thead>
      <tr>
        <th>Column 1</th>
        <th>Column 2</th>
      </tr>
    </thead>
    <tbody>
      <tr>
        <td>Data 1</td>
        <td>Data 2</td>
      </tr>
    </tbody>
  </table>
</div>
```

### Layouts

```html
<!-- KPI Grid -->
<section class="kpis">
  <article class="kpi">...</article>
  <article class="kpi">...</article>
  <!-- 6 columns on desktop, 3 on tablet, 2 on mobile -->
</section>

<!-- Hero Grid (2:1 ratio) -->
<section class="grid-hero">
  <article class="panel">...</article>
  <article class="panel">...</article>
</section>

<!-- Trio Grid (equal columns) -->
<section class="grid-trio">
  <article class="panel">...</article>
  <article class="panel">...</article>
  <article class="panel">...</article>
</section>
```

## Typography Classes

```html
<h1 class="heading-display">Display Heading</h1>
<p class="text-body">Body text</p>
<code class="text-mono">Monospace text</code>
<span class="text-label">Label</span>
<span class="text-hint">Hint text</span>
<div class="text-value text-cyan">42</div>
```

## Ambient Effects

```html
<body>
  <!-- Ambient orbs -->
  <div class="orb orb-1"></div>
  <div class="orb orb-2"></div>
  <div class="orb orb-3"></div>
  
  <!-- Content -->
  <div class="shell">
    <!-- Your content here -->
  </div>
</body>
```

## Chart Configuration

```javascript
import { applyChartTheme, chartColors } from './design-system/chart-theme.js';

// Apply theme globally
applyChartTheme(Chart);

// Use colors in your charts
new Chart(ctx, {
  type: 'line',
  data: {
    datasets: [{
      borderColor: chartColors[0],
      backgroundColor: chartColors[0] + '22'
    }]
  }
});
```

## Animations

```javascript
import { entranceAnimation, fadeIn, staggerIn } from './design-system/animations.js';

// Page load animation
entranceAnimation();

// Animate new content
fadeIn('.new-element');

// Animate list items
staggerIn('.list-item');
```

## Responsive Breakpoints

- **Desktop**: > 1200px (6-column KPI grid)
- **Tablet**: 640px - 1200px (3-column KPI grid)
- **Mobile**: < 640px (2-column KPI grid)

## Browser Support

- Chrome/Edge 90+
- Firefox 88+
- Safari 14+

## License

MIT
