/* Versión para navegador de los algoritmos propios de rsa_math.py. */
const $ = id => document.getElementById(id);
const six = value => String(value).padStart(6, '0');
const three = value => String(value).padStart(3, '0');
const visible = value => JSON.stringify(value).replaceAll(' ', '·');

function integer(value, name) {
  const text = String(value).trim();
  if (!/^[+-]?[0-9]+$/.test(text)) throw Error(`${name} debe ser un número entero.`);
  return BigInt(text);
}
function prime(value) {
  const n = Number(value);
  if (n < 2) return false;
  if (n === 2) return true;
  if (n % 2 === 0) return false;
  for (let divisor = 3; divisor * divisor <= n; divisor += 2) if (n % divisor === 0) return false;
  return true;
}
function gcd(a, b) {
  while (b !== 0n) [a, b] = [b, a % b];
  return a < 0n ? -a : a;
}
function inverse(value, modulus) {
  let [oldR, r, oldX, x] = [value, modulus, 1n, 0n];
  while (r !== 0n) {
    const quotient = oldR / r;
    [oldR, r] = [r, oldR - quotient * r];
    [oldX, x] = [x, oldX - quotient * x];
  }
  if (oldR !== 1n) throw Error('e no tiene inverso módulo φ.');
  return (oldX % modulus + modulus) % modulus;
}
function power(base, exponent, modulus) {
  // mpower2: cuadrados sucesivos con reducción módulo n en cada llamada.
  if (exponent === 0n) return 1n % modulus;
  const half = power(base, exponent / 2n, modulus);
  const square = half * half % modulus;
  return exponent % 2n === 1n ? (base * square) % modulus : square;
}
function trace(base, exponent, modulus) {
  const lines = [];
  function visit(exp, level) {
    if (exp === 0n) return 1n % modulus;
    const half = visit(exp / 2n, level + 1);
    const answer = exp % 2n ? (base * half * half) % modulus : (half * half) % modulus;
    lines.push(`Nivel ${level}: exponente ${exp}, mitad ${exp / 2n}, resultado parcial ${half}, ${exp % 2n ? 'impar' : 'par'} → ${answer}`);
    return answer;
  }
  const result = visit(exponent, 1);
  lines.push(`Resultado: ${six(result)}`);
  return lines.join('\n');
}
function parameters(pText, qText, eText) {
  const p = integer(pText, 'p'), q = integer(qText, 'q'), e = integer(eText, 'e');
  const n = p * q;
  if (n <= 126126n || n >= 1000000n) throw Error(`n = p × q = ${n} debe cumplir 126126 < n < 1000000.`);
  if (!prime(p)) throw Error('p debe ser primo.');
  if (!prime(q)) throw Error('q debe ser primo.');
  if (p === q) throw Error('p y q deben ser primos distintos.');
  const phi = (p - 1n) * (q - 1n);
  if (e <= 1n) throw Error('e debe ser mayor que 1.');
  if (gcd(e, phi) !== 1n) throw Error(`MCD(e, φ) debe ser 1; actualmente es ${gcd(e, phi)}.`);
  return {p, q, e, n, phi};
}
function encrypt(message, key) {
  if (!message.length) throw Error('M debe contener al menos un carácter.');
  for (let i = 0; i < message.length; i++) {
    const code = message.charCodeAt(i);
    if (code < 32 || code > 126) throw Error(`El carácter en la posición ${i + 1} no pertenece al ASCII imprimible (032 a 126).`);
  }
  const length = message.length, padded = message + (length % 2 ? ' ' : '');
  const blocks = [];
  for (let i = 0; i < padded.length; i += 2) {
    const pair = padded.slice(i, i + 2), codes = [pair.charCodeAt(0), pair.charCodeAt(1)];
    const m = BigInt(codes[0] * 1000 + codes[1]), c = power(m, key.e, key.n);
    blocks.push({pair, codes, m, c, trace: trace(m, key.e, key.n)});
  }
  return {length, padded, blocks, ciphertext: blocks.map(b => six(b.c)).join(' ')};
}
function decrypt(ciphertext, lengthText, key) {
  if (!/^[0-9]{6}( [0-9]{6})*$/.test(ciphertext)) throw Error('C debe contener bloques de exactamente seis dígitos, separados por un único espacio.');
  const values = ciphertext.split(' ').map(text => BigInt(text));
  values.forEach((value, i) => { if (value >= key.n) throw Error(`El bloque ${i + 1} debe cumplir 0 ≤ c < n (${key.n}).`); });
  const lengthValue = integer(lengthText, 'L');
  if (lengthValue < 0n) throw Error('L no puede ser negativa.');
  const k = BigInt(values.length);
  if (lengthValue !== 2n * k && lengthValue !== 2n * k - 1n) throw Error(`Con ${k} bloque(s), L debe ser ${2n * k} o ${2n * k - 1n}.`);
  const d = inverse(key.e, key.phi);
  const blocks = values.map((c, i) => {
    const m = power(c, d, key.n), text = six(m), codes = [Number(text.slice(0, 3)), Number(text.slice(3))];
    if (codes.some(code => code < 32 || code > 126)) throw Error(`El bloque ${i + 1} recupera un código ASCII fuera del rango permitido (032 a 126).`);
    return {c, m, codes, pair: String.fromCharCode(...codes), trace: trace(c, d, key.n)};
  });
  const padded = blocks.map(b => b.pair).join(''), filler = lengthValue % 2n === 1n;
  if (filler && !padded.endsWith(' ')) throw Error('L indica relleno, pero el último carácter recuperado no es un espacio.');
  const message = filler ? padded.slice(0, -1) : padded;
  return {d, blocks, padded, filler, message, length: Number(lengthValue)};
}
function table(blocks, operation) {
  const wrapper = document.createElement('div'); wrapper.className = 'table-wrap';
  const table = document.createElement('table');
  const header = document.createElement('tr');
  for (const label of ['#', 'Pareja', 'ASCII', 'm (6 dígitos)', 'c (6 dígitos)', 'Cálculo']) {
    const th = document.createElement('th'); th.textContent = label; header.append(th);
  }
  table.append(header);
  blocks.forEach((block, index) => {
    const row = document.createElement('tr');
    for (const value of [index + 1, visible(block.pair), block.codes.map(three).join(' '), six(block.m), six(block.c)]) {
      const cell = document.createElement('td'); cell.textContent = value; row.append(cell);
    }
    const cell = document.createElement('td'), details = document.createElement('details');
    const summary = document.createElement('summary'); summary.textContent = `Ver ${operation}`;
    const pre = document.createElement('pre'); pre.className = 'trace'; pre.textContent = block.trace;
    details.append(summary, pre); cell.append(details); row.append(cell); table.append(row);
  });
  wrapper.append(table); return wrapper;
}
function showError(operation, error) {
  $(`${operation}-result`).hidden = true;
  $(`${operation}-error`).textContent = error.message;
  $(`${operation}-error`).hidden = false;
  if (operation === 'encrypt') $('transfer').disabled = true;
}
let lastEncryption = null;
if (typeof document !== 'undefined') {
$('encrypt').addEventListener('click', () => {
  try {
    const key = parameters($('p').value, $('q').value, $('e').value);
    lastEncryption = {key, ...encrypt($('message').value, key)};
    $('encrypt-error').hidden = true;
    $('encrypt-summary').textContent = `n = ${key.n} · φ = ${key.phi} · llave pública = (${key.e}, ${key.n}) · L = ${lastEncryption.length} · relleno: ${lastEncryption.length % 2 ? 'sí' : 'no'}`;
    $('cipher-output').value = lastEncryption.ciphertext;
    $('length-output').value = lastEncryption.length;
    $('encrypt-blocks').replaceChildren(table(lastEncryption.blocks, 'm^e mod n'));
    $('encrypt-result').hidden = false; $('transfer').disabled = false;
  } catch (error) { lastEncryption = null; showError('encrypt', error); }
});
$('decrypt').addEventListener('click', () => {
  try {
    const key = parameters($('p').value, $('q').value, $('e').value);
    const result = decrypt($('cipher-input').value, $('length-input').value, key);
    $('decrypt-error').hidden = true;
    $('decrypt-summary').textContent = `n = ${key.n} · φ = ${key.phi} · d = ${result.d} · llave privada = (${result.d}, ${key.n}) · L = ${result.length} · relleno retirado: ${result.filler ? 'sí' : 'no'}`;
    $('message-output').value = result.message;
    $('visible-spaces').textContent = `Antes de retirar relleno: ${visible(result.padded)} · M: ${visible(result.message)} (· representa un espacio)`;
    $('decrypt-blocks').replaceChildren(table(result.blocks, 'c^d mod n'));
    $('decrypt-result').hidden = false;
  } catch (error) { showError('decrypt', error); }
});
$('transfer').addEventListener('click', () => {
  if (!lastEncryption) return;
  $('p').value = lastEncryption.key.p; $('q').value = lastEncryption.key.q; $('e').value = lastEncryption.key.e;
  $('cipher-input').value = lastEncryption.ciphertext; $('length-input').value = lastEncryption.length;
  $('decrypt-panel').scrollIntoView({behavior: 'smooth'});
});
$('example').addEventListener('click', () => { $('p').value = 367; $('q').value = 373; $('e').value = 17; $('message').value = 'RSA'; });
for (const [button, field] of [['copy-c', 'cipher-output'], ['copy-l', 'length-output']]) {
  $(button).addEventListener('click', async () => {
    try { await navigator.clipboard.writeText($(field).value); }
    catch { $(field).focus(); $(field).select(); }
  });
}
}
if (typeof module !== 'undefined') module.exports = {parameters, encrypt, decrypt, power};
