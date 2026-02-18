/**
 * GSAP Animation Utilities
 * Observatory Analytics Design System
 */

/**
 * Standard entrance animation for page load
 */
export function entranceAnimation() {
  if (typeof gsap === 'undefined') return;
  
  gsap.from('.masthead', {
    y: -30,
    opacity: 0,
    duration: 0.8,
    ease: 'power3.out'
  });
  
  gsap.from('.controls', {
    y: 20,
    opacity: 0,
    duration: 0.6,
    delay: 0.2,
    ease: 'power3.out'
  });
  
  gsap.from('.kpi', {
    y: 30,
    opacity: 0,
    duration: 0.5,
    stagger: 0.07,
    delay: 0.3,
    ease: 'power3.out'
  });
  
  gsap.from('.panel', {
    y: 40,
    opacity: 0,
    duration: 0.6,
    stagger: 0.1,
    delay: 0.5,
    ease: 'power3.out'
  });
  
  gsap.from('.table-section', {
    y: 40,
    opacity: 0,
    duration: 0.6,
    delay: 0.9,
    ease: 'power3.out'
  });
}

/**
 * Fade in animation for dynamic content
 */
export function fadeIn(selector, options = {}) {
  if (typeof gsap === 'undefined') return;
  
  const defaults = {
    opacity: 0,
    y: 20,
    duration: 0.4,
    ease: 'power2.out'
  };
  
  gsap.from(selector, { ...defaults, ...options });
}

/**
 * Stagger animation for lists
 */
export function staggerIn(selector, options = {}) {
  if (typeof gsap === 'undefined') return;
  
  const defaults = {
    opacity: 0,
    y: 20,
    duration: 0.4,
    stagger: 0.05,
    ease: 'power2.out'
  };
  
  gsap.from(selector, { ...defaults, ...options });
}
