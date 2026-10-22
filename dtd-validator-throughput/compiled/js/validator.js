// DTD validation of DITA topics with validators compiled from the DTDs.
//
// generated.js (made by compiled/gen.py) holds every content model as a
// minimized DFA plus the attribute declarations, as typed-array tables;
// nothing DTD-related is parsed at run time. saxes supplies the XML events.
'use strict';
const path = require('path');
const { SaxesParser } = require('saxes');
const g = require(process.env.DITA_GENERATED_JS || path.join(__dirname, '../../work-gen/generated.js'));

const EMPTY = 1, ANY = 2, MIXED = 3, ELEMENT = 4;
const DEAD = 0xffffffff; // content state after an error: one bad child is reported once
const T_CDATA = 0, T_ID = 1, T_IDREF = 2, T_IDREFS = 3, T_NMTOKEN = 6, T_NMTOKENS = 7;
const D_REQUIRED = 1, D_FIXED = 2;

const NAME_START = ':A-Z_a-z\\u00C0-\\u00D6\\u00D8-\\u00F6\\u00F8-\\u02FF\\u0370-\\u037D\\u037F-\\u1FFF' +
  '\\u200C-\\u200D\\u2070-\\u218F\\u2C00-\\u2FEF\\u3001-\\uD7FF\\uF900-\\uFDCF\\uFDF0-\\uFFFD\\u{10000}-\\u{EFFFF}';
const NAME_CHAR = NAME_START + '\\-.0-9\\u00B7\\u0300-\\u036F\\u203F-\\u2040';
const IS_NAME = new RegExp(`^[${NAME_START}][${NAME_CHAR}]*$`, 'u');
const IS_NMTOKEN = new RegExp(`^[${NAME_CHAR}]+$`, 'u');
const IS_WS = /^[ \t\r\n]*$/;

const SHELL_BY_PUBLIC = new Map(g.SHELLS.map((s) => [s.publicId, s]));

function step(state, sym) {
  let lo = g.TRANS_OFF[state], hi = g.TRANS_OFF[state + 1] - 1;
  while (lo <= hi) {
    const mid = (lo + hi) >> 1, s = g.TRANS_SYM[mid];
    if (s === sym) return g.TRANS_NEXT[mid];
    if (s < sym) lo = mid + 1; else hi = mid - 1;
  }
  return -1;
}

/** Non-CDATA attribute normalization: trim and collapse runs of spaces. */
function collapse(v) {
  return v.indexOf('  ') < 0 && v[0] !== ' ' && v[v.length - 1] !== ' '
    ? v : v.split(' ').filter((w) => w).join(' ');
}

function enumHas(e, v) {
  for (let i = g.ENUM_OFF[e], end = g.ENUM_OFF[e + 1]; i < end; i++) if (g.STRS[g.ENUM_VALS[i]] === v) return true;
  return false;
}

/** Returns { errors, messages } for one document's text. */
function validate(text, verbose) {
  let errors = 0, shell = null, doctypeName = '', seenRoot = false, stop = false;
  const messages = verbose ? [] : null;
  const kinds = [], states = [];
  const ids = new Set(), idrefs = [];
  const error = (msg) => { errors++; if (messages) messages.push(typeof msg === 'function' ? msg() : msg); };

  const contentText = (whitespace, cdata) => {
    const top = kinds.length - 1;
    if (top < 0 || states[top] === DEAD) return;
    const k = kinds[top];
    if (k === EMPTY || (k === ELEMENT && (!whitespace || cdata))) {
      states[top] = DEAD;
      error('character data not allowed here');
    }
  };

  const end = () => {
    const k = kinds.pop(), s = states.pop();
    if ((k === ELEMENT || k === MIXED) && s !== DEAD && !g.STATE_FINAL[s]) error('element content incomplete');
  };

  const p = new SaxesParser({ position: false });
  p.on('error', (e) => { if (!stop) error(`not well-formed: ${e.message}`); stop = true; });
  p.on('doctype', (d) => {
    doctypeName = d.trim().split(/\s/)[0];
    if (d.includes('[')) return error('internal DTD subsets are not supported');
    const m = /PUBLIC\s+(["'])(.*?)\1/.exec(d);
    shell = m ? SHELL_BY_PUBLIC.get(m[2]) || null : null;
    if (!shell) error(`no compiled DTD for public id '${m ? m[2] : ''}'`);
    else Object.assign(p.ENTITIES, shell.entities);
  });
  p.on('opentag', (tag) => {
    if (stop) return;
    if (!shell) { if (!seenRoot) error('no DTD found'); stop = true; return; }
    seenRoot = true;
    const name = tag.name;
    const id = g.ELEM_ID.get(name);
    const declared = id !== undefined && shell.kind[id] !== 0;
    const top = kinds.length - 1;
    if (top < 0) {
      if (name !== doctypeName) error(`root element ${name} does not match DOCTYPE`);
    } else {
      const pk = kinds[top];
      if ((pk === EMPTY || pk === MIXED || pk === ELEMENT) && states[top] !== DEAD) {
        const next = pk === EMPTY || id === undefined ? -1 : step(states[top], id);
        if (next >= 0) states[top] = next;
        else { states[top] = DEAD; error(`element ${name} not allowed here`); }
      }
    }
    if (!declared) {
      error(`no declaration for element ${name}`);
      kinds.push(ANY); states.push(DEAD);
      if (tag.isSelfClosing) end();
      return;
    }
    const al = shell.alist[id], lo = g.ALIST_OFF[al], hi = g.ALIST_OFF[al + 1];
    let required = 0;
    const attrs = tag.attributes;
    for (const key in attrs) {
      const aid = g.ATTR_ID.get(key);
      let d = -1;
      for (let i = lo; i < hi; i++) if (g.AD_ATTR[g.ALIST[i]] === aid) { d = g.ALIST[i]; break; }
      if (d < 0) { error(() => `no declaration for attribute ${key}`); continue; }
      const type = g.AD_TYPE[d];
      const v = type === T_CDATA ? attrs[key] : collapse(attrs[key]);
      let ok;
      switch (type) {
        case T_CDATA: ok = true; break;
        case T_ID: ok = IS_NAME.test(v) && !ids.has(v); ids.add(v); break;
        case T_IDREF: ok = IS_NAME.test(v); idrefs.push(v); break;
        case T_IDREFS: ok = v.split(' ').every((r) => (idrefs.push(r), IS_NAME.test(r))); break;
        case T_NMTOKEN: ok = IS_NMTOKEN.test(v); break;
        case T_NMTOKENS: ok = v.split(' ').every((t) => IS_NMTOKEN.test(t)); break;
        case 8: case 9: ok = enumHas(g.AD_ENUM[d], v); break;
        default: ok = false; // ENTITY/ENTITIES: the DTDs declare no unparsed entities
      }
      if (!ok) error(() => `bad value '${v}' for attribute ${key}`);
      const def = g.AD_DEFAULT[d];
      if (def === D_REQUIRED) required++;
      else if (def === D_FIXED && g.STRS[g.AD_FIXED[d]] !== v) error(() => `attribute ${key} must be fixed`);
    }
    if (required < shell.nreq[id]) error(() => `required attribute missing on ${name}`);
    kinds.push(shell.kind[id]); states.push(shell.start[id]);
    if (tag.isSelfClosing) end();
  });
  p.on('closetag', (tag) => { if (!stop && !tag.isSelfClosing && kinds.length) end(); });
  p.on('text', (t) => { if (!stop) contentText(IS_WS.test(t), false); });
  p.on('cdata', () => { if (!stop) contentText(false, true); });
  try {
    p.write(text).close();
  } catch (e) {
    if (!stop) error(`not well-formed: ${e.message}`);
    stop = true;
  }
  if (!stop) {
    if (!seenRoot) error('no root element');
    for (const r of idrefs) if (!ids.has(r)) error(`IDREF '${r}' has no matching ID`);
  }
  return { errors, messages };
}

/** Baseline: the same saxes parse with no validation work. */
function parseOnly(text) {
  let errors = 0;
  const p = new SaxesParser({ position: false });
  p.on('error', () => { errors = 1; });
  p.on('opentag', () => {});
  p.on('text', () => {});
  try { p.write(text).close(); } catch (e) { errors = 1; }
  return { errors, messages: null };
}

module.exports = { validate, parseOnly };
