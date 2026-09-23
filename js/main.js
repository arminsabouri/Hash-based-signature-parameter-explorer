import { scheme } from './scheme.js';
import lamport, { lamportGrid } from './schemes/lamport.js';
import wots, { wotsCChains, wotsChains } from './schemes/wots.js';
import xmss, { xmssTree } from './schemes/xmss.js';
import xmssMt, { xmssMtTree } from './schemes/xmss-mt.js';
import fxmss, { fxmssTree } from './schemes/fxmss.js';
import fors, { forsForest } from './schemes/fors.js';
import sphincs, { sphincsDiagram } from './schemes/sphincs.js';

const schemes = { lamport, wots, xmss, 'xmss-mt': xmssMt, fxmss, fors, sphincs };

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
  Alpine.data('wotsCChains', wotsCChains);
  Alpine.data('xmssTree', xmssTree);
  Alpine.data('xmssMtTree', xmssMtTree);
  Alpine.data('fxmssTree', fxmssTree);
  Alpine.data('forsForest', forsForest);
  Alpine.data('sphincsDiagram', sphincsDiagram);
});
