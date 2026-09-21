import { scheme } from './scheme.js';
import lamport, { lamportGrid } from './schemes/lamport.js';
import wots, { wotsChains } from './schemes/wots.js';

const schemes = { lamport, wots };

// Fill panel placeholders from their <template> before Alpine walks the DOM.
// This module loads before the deferred Alpine script.
for (const el of document.querySelectorAll('[data-template]')) {
  el.append(document.getElementById(el.dataset.template).content.cloneNode(true));
}

document.addEventListener('alpine:init', () => {
  // Typesets text containing \( \) math with KaTeX whenever the value changes.
  Alpine.directive('katex', (el, { expression }, { evaluateLater, effect }) => {
    const get = evaluateLater(expression);
    effect(() => get((value) => {
      el.textContent = value ?? '';
      renderMathInElement(el);
    }));
  });

  Alpine.data('scheme', (id) => scheme(schemes[id]));
  Alpine.data('lamportGrid', lamportGrid);
  Alpine.data('wotsChains', wotsChains);
});
